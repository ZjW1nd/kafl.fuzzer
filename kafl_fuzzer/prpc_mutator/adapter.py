from typing import List, Optional

from . import prpc_datafile_reader as reader
from . import prpc_datafile_writer as writer
from . import prpc_mutator as mut


class PRPCMutatorAdapter:
    """
    Thin wrapper around legacy prpc_mutator to provide a simple class interface
    without altering original mutation logic.
    """

    def __init__(self, pathpool: Optional[List[bytes]] = None):
        self.pathpool: Optional[List[bytes]] = pathpool

    def parse(self, payload2: bytes):
        return reader.parse(payload2)

    def serialize(self, calls) -> bytes:
        return writer.serialize(calls)

    def update_pathpool(self, calls) -> None:
        # Ensure mutator uses current pool; fall back to existing global pool
        if self.pathpool is not None:
            mut.set_pathpool(list(self.pathpool))
        for call in calls:
            mut.updatepathpool(call)
        # Capture updated pool for next round
        self.pathpool = list(mut.pathpool)

    def mutate(self, payload2: bytes, num_mutations: int = 1) -> bytes:
        calls = reader.parse(payload2)
        # deletion chance scales with call count (align with original logic)
        del_chance = mut.DELETECALLCHANCE if len(calls) <= 30 else 0.5

        for _ in range(max(1, num_mutations)):
            if self.pathpool is not None:
                mut.set_pathpool(list(self.pathpool))
            calls = mut.get_mutated_calls(del_chance, calls)
            # keep pool in sync after each iteration
            self.pathpool = list(mut.pathpool)

        return writer.serialize(calls)
