"""InvestigationService - assignment, notes, recommended outcomes."""


class InvestigationService:
    @staticmethod
    def assign(report, investigator):
        raise NotImplementedError("FR-AD6: assign investigator")

    @staticmethod
    def add_note(report, investigator, note_text, recommendation=None):
        raise NotImplementedError("FR-I8: investigation note + recommendation")
