"""One durable dispatch per closed subject; unresolved intent never resends."""
from datetime import datetime, timezone
from sqlalchemy import select, update
from .database import begin_mutation_write
from .dss_language_broker import digest, selected_subjects, subject_binding, validate_subject_result
from .migrations.versions.v0011_dss_language_ledger import language_cases


class DssLanguageUncertain(ValueError):
    pass


class LanguageLedger:
    def __init__(self, session_factory):
        self.session_factory = session_factory

    def reserve(self, request: dict, subject: str) -> dict | None:
        if subject not in selected_subjects(request):
            raise ValueError("language ledger subject is outside its selection")
        binding_hash = digest(subject_binding(subject))
        with self.session_factory() as session:
            begin_mutation_write(session)
            row = session.execute(select(language_cases).where(
                language_cases.c.request_id == request["request_id"],
                language_cases.c.subject == subject).with_for_update()).mappings().one_or_none()
            if row is not None:
                if row["request_hash"] != digest(request) or row["binding_hash"] != binding_hash:
                    raise ValueError("language ledger request/source binding differs")
                if row["state"] != "SETTLED":
                    raise DssLanguageUncertain(subject + ": prior dispatch is unresolved; automatic replay is forbidden")
                result = validate_subject_result(subject, row["result"])
                if row["result_hash"] != digest(result):
                    raise ValueError("language ledger result digest differs")
                session.commit()
                return result
            session.execute(language_cases.insert().values(request_id=request["request_id"],
                subject=subject, execution_id=request["execution_id"], request_hash=digest(request), request=request,
                binding_hash=binding_hash, state="DISPATCHING", created_at=datetime.now(timezone.utc)))
            session.commit()
        return None

    def settle(self, request: dict, subject: str, result: dict) -> None:
        checked = validate_subject_result(subject, result)
        if subject not in selected_subjects(request):
            raise ValueError("language ledger result is outside its selection")
        with self.session_factory() as session:
            begin_mutation_write(session)
            changed = session.execute(update(language_cases).where(
                language_cases.c.request_id == request["request_id"], language_cases.c.subject == subject,
                language_cases.c.request_hash == digest(request),
                language_cases.c.binding_hash == digest(subject_binding(subject)),
                language_cases.c.state == "DISPATCHING").values(state="SETTLED", result=checked,
                    result_hash=digest(checked), settled_at=datetime.now(timezone.utc)))
            if changed.rowcount != 1:
                raise ValueError("language ledger settlement lacks its original intent")
            session.commit()

    def result(self, request: dict, subject: str) -> dict:
        with self.session_factory() as session:
            row = session.execute(select(language_cases).where(
                language_cases.c.request_id == request["request_id"], language_cases.c.subject == subject)).mappings().one_or_none()
            if (row is None or row["state"] != "SETTLED" or row["request_hash"] != digest(request)
                    or row["binding_hash"] != digest(subject_binding(subject))):
                raise DssLanguageUncertain(subject + ": no authoritative completed DSS result")
            result = validate_subject_result(subject, row["result"])
            if row["result_hash"] != digest(result):
                raise ValueError("language ledger result digest differs")
            return result
