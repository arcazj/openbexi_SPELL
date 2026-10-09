"""Generate the Kafka image from exact vendor artifact hashes; check before release."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


def generated(root=ROOT):
    lock=json.loads((root / "contracts/dss/kafka_dependency_lock.json").read_bytes())
    if lock["schema_version"] != "openbexi.dss.kafka-dependencies/1" or lock["base"] != (
        "apache/kafka:4.3.1@sha256:77e3df9054047a88b520d0cc46e16696d3b22022e1d580aeccd2632df6532837"):
        raise ValueError("Kafka security base identity differs")
    lines=["# Generated from contracts/dss/kafka_dependency_lock.json; do not edit by hand.",
           "FROM scratch AS security-inputs"]
    names=set()
    for row in lock["artifacts"]:
        url=urlsplit(row["url"])
        name=url.path.rsplit("/",1)[-1]
        kind=row.get("kind")
        fields={"kind","name","version","url","sha256","size"} | ({"group"} if kind=="MAVEN" else set())
        if (set(row)!=fields or not re.fullmatch(r"[a-z0-9]+(?:[-.][a-z0-9]+)*",row.get("name",""))
            or not re.fullmatch(r"[0-9][A-Za-z0-9_.+-]*",row.get("version",""))):
            raise ValueError("Kafka dependency coordinate differs")
        filename=f"{row['name']}-{row['version']}." + ("apk" if kind=="APK" else "jar")
        expected_url=("https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/" + filename if kind=="APK" else
            "https://repo.maven.apache.org/maven2/" + row.get("group","").replace(".","/") +
            f"/{row['name']}/{row['version']}/{filename}")
        if kind=="MAVEN" and not re.fullmatch(r"[a-z0-9]+(?:\.[a-z0-9]+)+",row["group"]):
            raise ValueError("Kafka Maven group differs")
        if (url.scheme != "https" or url.netloc not in {"dl-cdn.alpinelinux.org","repo.maven.apache.org"}
            or url.query or url.fragment or name in names or not re.fullmatch(r"[A-Za-z0-9_.-]+\.(apk|jar)",name)
            or not re.fullmatch(r"[0-9a-f]{64}",row["sha256"]) or type(row["size"]) is not int
            or not 0 < row["size"] <= 20_000_000 or kind not in {"APK","MAVEN"}
            or row["url"]!=expected_url):
            raise ValueError("Kafka dependency artifact identity differs")
        names.add(name)
        folder="apks" if row["kind"]=="APK" else "jars"
        lines.append(f"ADD --checksum=sha256:{row['sha256']} {row['url']} /{folder}/{name}")
    jars=[row for row in lock["artifacts"] if row["kind"]=="MAVEN"]
    if len(jars)!=21 or len(lock["artifacts"])!=27:
        raise ValueError("Kafka patched dependency inventory differs")
    old=[f"/opt/kafka/libs/{row['name']}-" + ("2.21.2" if row['name'].startswith('jackson-') else
          "3.30.4" if row['name']=='jline' else "1.10.2" if row['name']=='lz4-java' else "12.0.34") + ".jar" for row in jars]
    lines += ["", "FROM " + lock["base"] + " AS secured-runtime", "ARG SPELL_PACKAGE_VERSION=0.19.0",
        'LABEL org.openbexi.spell.component="kafka" \\',
        '      org.openbexi.spell.scope="local-satellite-simulator" \\',
        '      org.openbexi.spell.package.version="${SPELL_PACKAGE_VERSION}"',
        "USER root", "COPY --from=security-inputs /apks/ /tmp/security-updates/",
        "RUN apk add --no-cache --no-network /tmp/security-updates/*.apk \\",
        "    && rm -f /tmp/security-updates/*.apk \\",
        "    && rm -f " + (" " + chr(92) + "\n        ").join(old) + " \\",
        "    && mkdir -p /var/lib/kafka/data /usr/local/share/openbexi \\",
        "    && chown 1000:1000 /var/lib/kafka/data",
        "COPY --chmod=0644 --from=security-inputs /jars/ /opt/kafka/libs/",
        "COPY contracts/dss/kafka_dependency_lock.json /usr/local/share/openbexi/kafka_dependency_lock.json",
        "", "# Copy only the secured filesystem: deleted vulnerable artifacts are absent from all delivered layers.",
        "FROM scratch", "COPY --from=secured-runtime / /", "ARG SPELL_PACKAGE_VERSION=0.19.0",
        'LABEL org.openbexi.spell.component="kafka" \\',
        '      org.openbexi.spell.scope="local-satellite-simulator" \\',
        '      org.openbexi.spell.package.version="${SPELL_PACKAGE_VERSION}"',
        'ENV PATH="/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \\',
        '    JAVA_HOME="/opt/java/openjdk" LANG="en_US.UTF-8" LANGUAGE="en_US:en" \\',
        '    LC_ALL="en_US.UTF-8" JAVA_VERSION="jdk-21.0.11+10"',
        "USER 1000:1000", 'ENTRYPOINT ["/__cacert_entrypoint.sh"]', 'CMD ["/etc/kafka/docker/run"]', ""]
    return "\n".join(lines).encode()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check",action="store_true")
    args=parser.parse_args()
    path=ROOT / "dss/kafka.Dockerfile"
    content=generated()
    if args.check:
        if path.read_bytes()!=content: raise ValueError("Kafka image recipe differs from the security lock")
        print("Kafka checksum-bound security image recipe: PASS")
    else: path.write_bytes(content)


if __name__=="__main__": main()
