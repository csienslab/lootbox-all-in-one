from abc import ABCMeta, abstractmethod
from typing import TypeVar, Generic

EvalAndProofT = TypeVar("EvalAndProofT")


class AbstractVDF(Generic[EvalAndProofT], metaclass=ABCMeta):
    @abstractmethod
    def __init__(self, bits: int, T: int):
        pass

    @abstractmethod
    def eval_and_prove(self, challenge: bytes) -> EvalAndProofT:
        pass

    @abstractmethod
    def verify(self, challenge: bytes, proof: EvalAndProofT) -> bool:
        pass

    @abstractmethod
    def extract_y(self, proof: EvalAndProofT) -> bytes:
        pass


EvalT = TypeVar("EvalT")
ProofT = TypeVar("ProofT")


class AggregateVDF(Generic[EvalT, ProofT], metaclass=ABCMeta):
    @abstractmethod
    def eval(self, challenges: list[bytes]) -> list[EvalT]:
        pass

    @abstractmethod
    def aggregate(self, challenges: list[bytes], ys: list[EvalT]) -> ProofT:
        pass

    @abstractmethod
    def verify(self, challenges: list[bytes], ys: list[EvalT], proof: ProofT) -> bool:
        pass


AccumulatorT = TypeVar("AccumulatorT")
AccumulationValueT = TypeVar("AccumulationValueT")
WitnessT = TypeVar("WitnessT")


class AbstractAccumulator(
    Generic[AccumulatorT, AccumulationValueT, WitnessT], metaclass=ABCMeta
):
    @abstractmethod
    def __init__(self, **kwargs):
        pass

    @abstractmethod
    def accumulate(self, X: list[bytes]) -> AccumulatorT:
        pass

    @abstractmethod
    def witgen(self, acc: AccumulatorT, X: list[bytes], index: int) -> WitnessT:
        pass

    @abstractmethod
    def verify(self, accval: AccumulationValueT, w: WitnessT, x: bytes) -> bool:
        pass

    @abstractmethod
    def get_accval(self, acc: AccumulatorT) -> AccumulationValueT:
        pass

    @abstractmethod
    def get_bytes(self, accval: AccumulationValueT) -> bytes:
        pass


NonMemWitnessT = TypeVar("NonMemWitnessT")


class AbstractUniversalAccumulator(
    AbstractAccumulator,
    Generic[AccumulatorT, AccumulationValueT, WitnessT, NonMemWitnessT],
    metaclass=ABCMeta,
):
    @abstractmethod
    def nonmemwitgen(
        self, acc: AccumulatorT, X: list[bytes], x: bytes
    ) -> NonMemWitnessT:
        pass

    @abstractmethod
    def nonmemverify(
        self, accval: AccumulationValueT, w: NonMemWitnessT, x: bytes
    ) -> bool:
        pass
