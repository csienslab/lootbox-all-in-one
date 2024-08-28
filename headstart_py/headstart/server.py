from flask import Flask, request, make_response
from werkzeug.exceptions import HTTPException
from flask.json.provider import JSONProvider
from apscheduler.schedulers.background import BackgroundScheduler
import atexit, logging, base64, json, msgpack
from headstart.stage import Stage, Phase
import headstart.public_key as public_key
from cryptography.hazmat.primitives import serialization


with open("priv.key", "rb") as f:
    priv_key = serialization.load_pem_private_key(f.read(), password=None, backend=None)
with open("pub.key", "rb") as f:
    public_bytes = f.read()


class RandomnessBeacon:
    def __init__(self, logger: logging.Logger, priv_key: public_key.Ed25519PrivateKey):
        self.logger = logger
        self.stages: list[Stage] = [Stage()]
        self.interval_seconds = 3
        self.W = 10
        self.priv_key = priv_key

    @property
    def current_stage(self):
        return self.stages[-1]

    @property
    def current_stage_index(self):
        return len(self.stages) - 1

    def get_stage(self, stage_idx: int):
        if not (0 <= stage_idx <= self.current_stage_index):
            raise ValueError("invalid stage")
        return self.stages[stage_idx]

    def get_stage_after_phase(self, stage_idx: int, phase: Phase):
        stage = self.get_stage(stage_idx)
        if stage.phase < phase:
            raise ValueError("not in correct phase")
        return stage

    def contribute(self, x: bytes):
        self.logger.debug(
            f"Contribution received",
            extra={"x": x.hex(), "stage": self.current_stage_index},
        )
        data_idx = self.current_stage.contribute(x)
        stage_idx = self.current_stage_index
        sig = public_key.sign(self.priv_key, x)
        return stage_idx, data_idx, sig

    def next_stage(self):
        self.logger.info(f"Starting next stage #{self.current_stage_index + 1}")
        self.current_stage.stop_contribution()
        prev_stages = self.stages[-self.W + 1 :]
        self.stages.append(Stage(prev_stages))

    def register_scheduler(self):
        scheduler = BackgroundScheduler()
        scheduler.add_job(
            func=self.next_stage, trigger="interval", seconds=self.interval_seconds
        )
        scheduler.start()
        atexit.register(lambda: scheduler.shutdown())
        self.scheduler = scheduler


def msgpackify(obj):
    resp = make_response(msgpack.packb(obj))
    resp.headers["Content-Type"] = "application/msgpack"
    return resp


app = Flask(__name__)
app.logger.setLevel(logging.INFO)


@app.errorhandler(HTTPException)
def handle_exception(e):
    """Return JSON instead of HTML for HTTP errors."""
    # start with the correct headers and status code from the error
    response = e.get_response()
    # replace the body with JSON
    response.data = json.dumps(
        {
            "code": e.code,
            "name": e.name,
            "description": e.description,
        }
    )
    response.content_type = "application/json"
    return response


beacon = RandomnessBeacon(app.logger, priv_key)
beacon.register_scheduler()


@app.get("/api/pubkey")
def pubkey():
    resp = make_response(public_bytes)
    resp.headers["Content-Type"] = "application/octet-stream"
    return resp


@app.get("/api/beacon_config")
def beacon_config():
    return msgpackify(
        {
            "interval_seconds": beacon.interval_seconds,
            "window_size": beacon.W,
        }
    )


@app.get("/api/info")
def info():
    return msgpackify(
        {
            "stage": beacon.current_stage_index,
            "phase": beacon.current_stage.phase.name,
            "contributions": len(beacon.current_stage.data),
        }
    )


@app.post("/api/contribute")
def contribute():
    try:
        x = base64.b64decode(request.json["randomness"])
    except:
        return (
            msgpackify(
                {"error": "no randomness provided or randomness isn't base64 encoded"}
            ),
            400,
        )
    stage_idx, data_idx, sig = beacon.contribute(x)
    return msgpackify({"stage": stage_idx, "data_index": data_idx, "signature": sig})


def get_stage(idx):
    if idx == -1:
        # for client implementation convenience
        return {
            "stage": -1,
            "phase": "DONE",
            "contributions": 0,
            "vdfy": b"",
            "accval": b"",
            "vdfchallenge": b"",
            "vdfproof": b"",
            "randomness": b"",
        }
    try:
        stage = beacon.get_stage(idx)
    except ValueError:
        return {"stage": idx, "phase": "NONE", "contributions": 0}
    ret = {
        "stage": idx,
        "phase": stage.phase.name,
        "contributions": len(stage.data),
    }
    if stage.phase >= Phase.EVALUATION:
        ret["accval"] = stage.get_acc_val()
    if stage.phase >= Phase.DONE:
        ret["vdfy"] = stage.get_final_y()
        ret["vdfproof"] = stage.get_vdf_proof()
    return ret


@app.get("/api/stage")
def stages():
    # inclusive
    start_idx = int(request.args.get("start", 0))
    end_idx = int(request.args.get("end", beacon.current_stage_index))
    return msgpackify([get_stage(idx) for idx in range(start_idx, end_idx + 1)])


@app.get("/api/stage/<int:stage_idx>")
def stage(stage_idx):
    return msgpackify(get_stage(stage_idx))


@app.get("/api/stage/<int:stage_idx>/accproof/<int:data_idx>")
def accproof(stage_idx, data_idx):
    stage = beacon.get_stage_after_phase(stage_idx, Phase.EVALUATION)
    return msgpackify(stage.get_acc_proof(data_idx))
