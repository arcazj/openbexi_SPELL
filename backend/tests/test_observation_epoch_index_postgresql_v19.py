"""Actual PostgreSQL generic plans use the bounded DSS epoch-event index."""
import os

import pytest
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

from backend.database import create_database
from backend.migrations.versions import v0012_dss_epoch_index as migration
from backend.tests import test_observation_repository as fixtures
from backend.tests.migration_support import reset_test_database
from backend.tests.test_observation_repository import observation_store
from backend.tests.test_observation_epoch_index_v19 import predecessor_store, assert_upgrade_and_authority


@pytest.mark.skipif(not os.getenv("SPELL_MIGRATION_TEST_DATABASE_URL"),
                   reason="dedicated PostgreSQL migration database not configured")
@pytest.mark.parametrize("rollback",[False,True])
def test_postgresql_epoch_index_upgrade_and_actual_forced_generic_plan(monkeypatch,request,rollback):
    url=os.environ["SPELL_MIGRATION_TEST_DATABASE_URL"]
    engine,_=create_database(url)
    reset_test_database(engine)
    engine.dispose()
    monkeypatch.setattr(fixtures,"create_database",lambda _:create_database(url))
    store=request.getfixturevalue("predecessor_store")
    repository,stream_id,stream_epoch=assert_upgrade_and_authority(store,monkeypatch,rollback=rollback)
    # Append enough retained, unrelated payloads to exercise the planner choice
    # that scanned56000 active-stream rows in the live failure.
    from backend.observation_models import ObservationOutboxEvent,ObservationStream
    from datetime import datetime,timezone
    with store[1].begin() as session:
        stream=session.get(ObservationStream,stream_id)
        first=stream.last_sequence
        for offset in range(0,60000,2000):
            session.execute(ObservationOutboxEvent.__table__.insert(),[
                {"id":f"generic-plan-{index}","stream_id":stream_id,"stream_epoch":stream_epoch,
                 "projection_sequence":first+index+1,"event_type":"telemetry.sample_observed",
                 "aggregate_type":"telemetry_sample","aggregate_id":str(index),
                 "payload":{"retained":index,"padding":"x"*512},"delivery_attempts":0,
                 "created_at":datetime(2026,10,3,tzinfo=timezone.utc)}
                for index in range(offset,offset+2000)])
        stream.last_sequence+=60000
    statement=repository._dss_epoch_query(stream_id,stream_epoch)
    dialect=postgresql.dialect(paramstyle="numeric_dollar")
    compiled=statement.compile(dialect=dialect)
    assert compiled.positiontup==["stream_id_1","stream_epoch_1","param_1"]
    with store[1]() as session:
        connection=session.connection()
        connection.exec_driver_sql("ANALYZE observation_outbox")
        connection.exec_driver_sql("SET LOCAL plan_cache_mode=force_generic_plan")
        connection.exec_driver_sql("PREPARE dss_epoch_plan(varchar,varchar,integer) AS "+str(compiled))
        # These are generated fixture UUIDs, quoted by SQLAlchemy, not input SQL.
        quote=postgresql.VARCHAR().literal_processor(dialect)
        arguments=",".join((quote(stream_id),quote(stream_epoch),"1"))
        result=connection.exec_driver_sql("EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) EXECUTE dss_epoch_plan("+arguments+")").scalar_one()[0]
        rows=connection.exec_driver_sql("EXECUTE dss_epoch_plan("+arguments+")").mappings().all()
        connection.exec_driver_sql("DEALLOCATE dss_epoch_plan")
    def nodes(row):
        return [row]+[node for child in row.get("Plans",[]) for node in nodes(child)]
    plan=nodes(result["Plan"])
    assert len(rows)==1 and rows[0]["payload"]["data"]["source_epoch"]=="epoch-"+"b"*64
    assert any(node.get("Index Name")==migration.INDEX_NAME for node in plan)
    assert not any(node["Node Type"] in {"Sort","Seq Scan","Bitmap Heap Scan"} for node in plan)
    assert sum(node.get("Rows Removed by Filter",0) for node in plan)==0
    assert result["Plan"].get("Shared Hit Blocks",0)+result["Plan"].get("Shared Read Blocks",0)<32
