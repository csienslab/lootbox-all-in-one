from headstart.stage import Parameters, Phase, Stage
from dataclasses import dataclass
import httpx, base64, msgpack, time, headstart.public_key as public_key
from cryptography.hazmat.primitives import serialization
from typing import Optional


@dataclass
class Contribution:
    value: bytes
    stage: int
    data_index: int
    signature: bytes


@dataclass
class StageInfo:
    stage: int
    phase: Phase
    contributions: int
    accval: Optional[bytes] = None
    vdfy: Optional[bytes] = None
    vdfproof: Optional[bytes] = None

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        if isinstance(self.phase, str):
            self.phase = Phase[self.phase]


class HeadStartClient:
    @staticmethod
    def from_server_url(url: str) -> "HeadStartClient":
        client = httpx.Client(base_url=url)
        pub_bytes = client.get("/api/pubkey").content
        pub_key = serialization.load_pem_public_key(pub_bytes)
        W = msgpack.unpackb(client.get("/api/beacon_config").content)["window_size"]
        return HeadStartClient(client, pub_key, W)

    def __init__(
        self, client: httpx.Client, pub_key: public_key.Ed25519PublicKey, W: int
    ):
        self.client = client
        self.pub_key = pub_key
        self.W = W

    def get_info(self) -> StageInfo:
        return StageInfo(**msgpack.unpackb(self.client.get("/api/info").content))

    def contribute(self, randomness: bytes) -> Contribution:
        ct = Contribution(
            value=randomness,
            **msgpack.unpackb(
                self.client.post(
                    "/api/contribute",
                    json={"randomness": base64.b64encode(randomness).decode()},
                ).content
            ),
        )
        if not public_key.verify(self.pub_key, ct.value, ct.signature):
            raise ValueError("invalid signature")
        return ct

    def get_stage(self, stage_idx: int) -> StageInfo:
        return StageInfo(
            **msgpack.unpackb(self.client.get(f"/api/stage/{stage_idx}").content)
        )

    def get_stages(self, start: int, end: int) -> list[StageInfo]:
        res = msgpack.unpackb(
            self.client.get(f"/api/stage", params={"start": start, "end": end}).content
        )
        return [StageInfo(**x) for x in res]

    def get_stage_until(
        self, stage_idx: int, phase: Phase, polling_interval=1
    ) -> StageInfo:
        while (info := self.get_stage(stage_idx)).phase < phase:
            time.sleep(polling_interval)
        return info

    def __accval(self, stage_idx: int) -> bytes:
        return msgpack.unpackb(
            self.client.get(f"/api/stage/{stage_idx}/accval").content
        )

    def __accproof(self, contribution: Contribution):
        return msgpack.unpackb(
            self.client.get(
                f"/api/stage/{contribution.stage}/accproof/{contribution.data_index}"
            ).content
        )

    def __vdfproof(self, stage: int) -> bytes:
        return msgpack.unpackb(self.client.get(f"/api/stage/{stage}/vdfproof").content)

    def __randomness(self, stage_idx: int) -> bytes:
        return msgpack.unpackb(
            self.client.get(f"/api/stage/{stage_idx}/randomness").content
        )

    def get_verified_randomness(
        self, contribution: Contribution, stage_idx: int, polling_interval=1
    ) -> bytes:
        self.get_stage_until(stage_idx, Phase.DONE, polling_interval)
        # our contribution are at contribution.stage
        # and we want to get the randomness at stage_idx
        # each vdf proof in a stage proves [max(stage_idx - W + 1, 0), stage_idx] stages
        # so we need to split the range into multiple ranges and round up correctly
        # e.g. if stage_idx = 10, W = 5, contribution.stage = 7
        # we need a proof for [6, 10]
        # e.g. if stage_idx = 103, W = 10, contribution.stage = 77
        # we need a proof for [76, 85], [85, 94], [94, 103]

        ranges = []
        target = stage_idx
        while target >= contribution.stage:
            ranges.append((max(target - self.W + 1, 0), target))
            target -= self.W
        ranges.reverse()
        start = ranges[0][0]
        end = ranges[-1][1]

        extra, *stages = self.get_stages(
            start - 1, end
        )  # we want an extra one to get the y

        # first, verify it is included in accumulator
        contributed_stage = next(
            stg for stg in stages if stg.stage == contribution.stage
        )
        accproof = self.__accproof(contribution)
        if not Parameters.accumulator.verify(
            contributed_stage.accval, accproof, contribution.value
        ):
            raise ValueError("accumulator verification failed")

        # then we construct the challenges and ys
        vdf_challenges = [
            Parameters.hash(cur.accval + prev.vdfy)
            for cur, prev in zip(stages, [extra] + stages)
        ]
        vdf_ys = [stg.vdfy for stg in stages]
        # verify the vdf proofs
        shifted_ranges = [(x - start, y - start) for x, y in ranges]
        for st_idx, ed_idx in shifted_ranges:
            challenges = vdf_challenges[st_idx : ed_idx + 1]
            ys = vdf_ys[st_idx : ed_idx + 1]
            proof = stages[ed_idx].vdfproof
            if not Parameters.avdf.verify(challenges, ys, proof):
                raise ValueError("vdf verification failed")

        target_stage = next(stg for stg in stages if stg.stage == stage_idx)
        return target_stage.vdfy


if __name__ == "__main__":
    client = HeadStartClient.from_server_url("http://localhost:5000")
    print(client.get_info())
    print(ct1 := client.contribute(b"peko"))
    print(ct2 := client.contribute(b"miko"))
    print(client.get_verified_randomness(ct1, ct1.stage + 12))
    print(client.get_verified_randomness(ct2, ct2.stage + 22))
    print(client.get_stage(ct1.stage))
