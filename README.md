# shadetrace
Open Java class fingerprints for detecting embedded libraries without metadata

## The problem
The shading is when a library is copied to another JAR and its metadata in META-INF/maven is lost. 
Then it is invisible to scanners. It's CVE is not visible as well. 

```
1) REGULAR APPLICATION (C0): the dependencies are as separate JARs

   app.jar                 log4j-core-2.14.1.jar
   └── com/example/...     ├── org/apache/logging/log4j/...
                           └── META-INF/maven/.../pom.properties  <-- "I am log4j-core 2.14.1"

   Scanner: sees file log4j-core-2.14.1.jar  ->  CVE-2021-44228 ✅


2) FAT JAR (C1): depenency classes are unpacked into one JAR

   app.jar
   ├── com/example/...
   ├── org/apache/logging/log4j/...                  <-- original packages
   └── META-INF/maven/org.apache.logging.log4j/
           log4j-core/pom.properties                 <-- metadata perzisted

   Scanner: find pom.properties  ->  CVE ✅


3) RELOCATION (C2): packages are renamed to avoid clashes

   org.apache.logging.log4j  ──►  com.example.shaded.logging.log4j

   app.jar
   ├── com/example/shaded/logging/log4j/...          <-- foreign name
   └── META-INF/maven/.../log4j-core/pom.properties  <-- still present

   Scanner: reads pom.properties, pacakege names do not matter ->  CVE ✅


4) RELOCATION + REMOVED METADATA (C3, C4, Netty in grpc, snappy in hadoop)

   app.jar
   ├── com/example/shaded/logging/log4j/...          <-- here is the vulnerable code
   └── META-INF/maven/  ✗  (filtered out)

   Scanner: "app-1.0.0.jar, nothing more"  ->  no CVE ❌
           ┌─────────────────────────────────────────────────────────┐
           │  the JNDI lookup code is still in the JAR and working,  │
           │  but nobody knows about it = silent vulnerability.      │
           └─────────────────────────────────────────────────────────┘


What a scanner actually reads

   pom.properties  ──►  name + version  ──►  CVE database  ──►  finding
        ▲
        └── if the metadata file is missing, the chain breaks at the first step.
            Classes are not compared, bytecode is not analyzed.
```

## The Solution

ShadeTrace recognizes embedded libraries by the content of its classes, not by reading the metadata.
- For all the classes it calculates bytecode fingerprints, after removing the packages names from its contents
  The relocation changes the package names, but the fingerprint is the same before the shading as well after the shading
- The open index links the fingerprints to the libraries coordinates (purl). It contains all versions of the libraries from the Maven Central repository with the vulnerabilities as well as the fixed versions, to be distinguishable
- When scanning, the tool calculates the fingerprints of the classes not described by metadata also in the nested JAR, WAR and EAR. It determines the library and its version by the matching score even when only a part of the library has been copied into the JAR
- The result is written into the CycloneDX SBOM together with the proof (what classes have been found) and the confidence rate. CycloneDX already have fields for this. The vulnerabilities will be linked to the result by the scanners using their own databases.
- The final SBOM can be sent to Grype or Dependency-Track
- The index is an open dataset, so any other tool can use it


## The actual experiment
The common open-source SCA tools find a library included in a different JAR.

### Testing Scenarios
| Case | Description |
|---|---|
|C0|the original library (the control case)|
|C1| Fat JAR without rlocation, metadata without change|
|C2| Fat JAR with relocation, metadata without change|
|C3| Fat JAR with relocation, without metdata (META-INF/maven, manifests)|
|C4| C3 embedded into WAR and that embedded into EAR |

            
### Main Results

All the tools work only when `META-INF/maven/.../pom.properties` stays in the JAR file. The relocation will not worsen the detection. 
When the metadata are removed, either synthetically (C3, C4) or in the real artifacts (Netty in grpc, snappy-java in hadoop), all fail. 
There was no fale vulnerability finding, but all the tools are making up the groupId of the unknown JARs.

### Where the tools failed

- **C3 a C4 (relocation and removed `META-INF/maven`):** Trivy, Syft, Grype nor OSV-Scanner found log4j-core nor commons-text. The result was 0 out of 2 components. They didn't report CVE-2021-44228, nor CVE-2022-42889. Embeding the JAR into the WAR and EAR didn't worsen it, C4 turned out the same as C3.
- **C1 a C2 had been found by all tools correctly,** s menom, verziou aj CVE. Shade plugin v C2 `META-INF/maven` knižnice naozaj ponechal, takže samotná relokácia detekciu nezhorší. Rozhodujú len metadáta.
- **grpc-netty-shaded 1.40.1:** includes Netty 4.1.52.Final without metadata. Version is detected from pom of not shaded `io.grpc:grpc-netty:1.40.1`. No tool found Netty (0 out of 14 components) and CVE-2021-21409 was not reported. The only finding from Trivy: outer JAR was identified by SHA1 and reported CVE-2025-55163 directly on `io.grpc:grpc-netty-shaded`. Syft, Grype and OSV gave it a bad group, and therefore found nothing.
- **hadoop-client-runtime 3.3.1:** is leaving 84 `pom.properties`, so all the tools found all 84 components and 58 findings. However all of them overlook snappy-java 1.1.8.2, that was relocated without metadata (CVE-2023-34453). It is a real case C3. The version was detected from pom of `org.apache.hadoop:hadoop-project:3.3.1` and file `org/apache/hadoop/shaded/org/xerial/snappy/VERSION`.
- **False components identities:**
  - Trivy marked neutral `app-1.0.0.jar` as `io.zeebe.zeeqs:app` (it tracked it in Java DB by the name and version).
  - Syft, Grype and OSV are guessing groupId = artifactId.
  - Syft assigned hadoop-client-runtime the group `org.apache.hadoop.thirdparty`.

### Overview by case
✅ = the tool found the embedded library with the right version and expected CVE (in case of Syft only the library as it is not searching for CVE). 
❌ = found nothing.

| Tool | C0 | C1 | C2 | C3 | C4 | grpc: Netty | hadoop: jackson-databind | hadoop: snappy-java |
|---|---|---|---|---|---|---|---|---|
| Trivy 0.76.1 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| Syft 1.55.0 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| Grype 0.121.0 (SBOM from Syft) | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| Grype 0.121.0 (directly the file) | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| OSV-Scanner 2.7.0 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| OWASP Dependency-Check | – | – | – | – | – | – | – | – |

## Successes, Fails and False Identities

| Tool | When succeeded | When failed | Falose components identities | Running time |
|---|---|---|---|---|
| Trivy | C0–C2: log4j-core 2.14.1 and commons-text 1.9 with CVE-2021-44228 and CVE-2022-42889. hadoop: 84 of 85 components, 58 findings. grpc: outer JAR identified by SHA1 and reported CVE-2025-55163 on `io.grpc:grpc-netty-shaded`. its the only tool, that reported something in grpc. | C3, C4: nothing. grpc: Netty 4.1.52.Final didn't find (0 of 14), CVE-2021-21409 didn't report. hadoop: snappy-java 1.1.8.2 without metadata didn't find (CVE-2023-34453). | `app-1.0.0.jar` marked as `io.zeebe.zeeqs:app:1.0.0` (C1–C4) | 0,3–0,7 s |
| Syft | C0–C2: both libraries with name and version. hadoop: 84 of 85. | C3, C4: nothing. grpc: Netty didn't find. hadoop: snappy-java didn't find. Does not search for vulnerabilities. | `app:app:1.0.0` (C1–C4), `grpc-netty-shaded:grpc-netty-shaded:1.40.1`, hadoop-client-runtime with group `org.apache.hadoop.thirdparty` | 1,3–1,9 s |
| Grype (SBOM from Syftu) | C0–C2: libraries and expected CVE. hadoop: CVE-2020-36518, 58 findings. | C3, C4: nothing. grpc: no finding, nor CVE-2025-55163, before it got a bad group from Syft. hadoop: snappy-java didn't find. | The same as Syft, components gets from its SBOM | 3,3–3,8 s |
| Grype (direct file) | The same as Grype on SBOM | The same as Grype on SBOM | The same as Syft, Syft runs inside Grype | 3,5–3,9 s |
| OSV-Scanner | C0–C2: libraries and expected CVE. hadoop: 84 of 85, 58 findings. | C3, C4: nič. grpc: no finding, groupId of the outer JARu guessed incorrectly. hadoop: snappy-java didn't find. | `app:app:1.0.0` (C3–C4), `grpc-netty-shaded:grpc-netty-shaded:1.40.1` | 0,7–1,7 s, hadoop 14 s (calls online API) |
| OWASP Dependency-Check | – | – | – | Not tested |

### Experiment Setup

- The own `pom.xml` of the fat JAR is not included (`addMavenDescriptor=false`). its `<dependencies>` would reveal the library otherwise.
- The scanned files have neutral names (`app-1.0.0.jar`, `app.ear`), to not guess the library from ithe name. C0 a the real artifacts have the original names.
- Relocation: `org.apache` → `com.example.shaded`. C3 filters out also `META-INF/maven/**` a `META-INF/MANIFEST.MF` of the embedded libraries (also transitives log4j-api and commons-lang3).
- Shade 3.6.0 didn't relocate 5 groups of log4j in `META-INF/versions/9`. No tool used that.
- For the hadoop, the CVE is expected for jackson-databind CVE-2020-36518. Embedded commons-text 1.4 doeas not have CVE-2022-42889, for versions 1.5 to 1.9.
- The vulnerabilities databases are downloaded before the scanning.
- No JAR was executed, all of them were scanned only in read-only mount.

### Detailed Results
| Case | Tool | Inserted library | Expected CVE | Reported CVE | Components found/inserted | Findings | False findings | False componets | Time (s) |
|---|---|---|---|---|---|---|---|---|---|
| ctext-C0 | trivy | commons-text:1.9 → name and version | CVE-2022-42889 | yes | 1/1 | 1 | 0 | 0 | 0.36 |
| ctext-C0 | syft | commons-text:1.9 → name and version | CVE-2022-42889 | – | 1/1 | – | – | 0 | 1.46 |
| ctext-C0 | grype-sbom | commons-text:1.9 → name and version | CVE-2022-42889 | yes | 1/1 | 1 | 0 | 0 | 3.52 |
| ctext-C0 | grype-file | commons-text:1.9 → name and version | CVE-2022-42889 | yes | 1/1 | 1 | 0 | 0 | 3.75 |
| ctext-C0 | osv-scanner | commons-text:1.9 → name and version | CVE-2022-42889 | yes | 1/1 | 1 | 0 | 0 | 1.12 |
| ctext-C1 | trivy | commons-text:1.9 → name and version | CVE-2022-42889 | yes | 2/2 | 2 | 0 | io.zeebe.zeeqs:app:1.0.0 | 0.39 |
| ctext-C1 | syft | commons-text:1.9 → name and version | CVE-2022-42889 | – | 2/2 | – | – | app:app:1.0.0 | 1.24 |
| ctext-C1 | grype-sbom | commons-text:1.9 → name and version | CVE-2022-42889 | yes | 2/2 | 2 | 0 | app:app:1.0.0 | 3.61 |
| ctext-C1 | grype-file | commons-text:1.9 → name and version | CVE-2022-42889 | yes | 2/2 | 2 | 0 | app:app:1.0.0 | 3.69 |
| ctext-C1 | osv-scanner | commons-text:1.9 → name and version | CVE-2022-42889 | yes | 2/2 | 2 | 0 | 0 | 1.1 |
| ctext-C2 | trivy | commons-text:1.9 → name and version | CVE-2022-42889 | yes | 2/2 | 2 | 0 | io.zeebe.zeeqs:app:1.0.0 | 0.35 |
| ctext-C2 | syft | commons-text:1.9 → name and version | CVE-2022-42889 | – | 2/2 | – | – | app:app:1.0.0 | 1.46 |
| ctext-C2 | grype-sbom | commons-text:1.9 → name and version | CVE-2022-42889 | yes | 2/2 | 2 | 0 | app:app:1.0.0 | 3.61 |
| ctext-C2 | grype-file | commons-text:1.9 → name and version | CVE-2022-42889 | yes | 2/2 | 2 | 0 | app:app:1.0.0 | 3.64 |
| ctext-C2 | osv-scanner | commons-text:1.9 → name and version | CVE-2022-42889 | yes | 2/2 | 2 | 0 | 0 | 1.13 |
| ctext-C3 | trivy | commons-text:1.9 → no | CVE-2022-42889 | no | 0/2 | 0 | 0 | io.zeebe.zeeqs:app:1.0.0 | 0.67 |
| ctext-C3 | syft | commons-text:1.9 → no | CVE-2022-42889 | – | 0/2 | – | – | app:app:1.0.0 | 1.25 |
| ctext-C3 | grype-sbom | commons-text:1.9 → no | CVE-2022-42889 | no | 0/2 | 0 | 0 | app:app:1.0.0 | 3.62 |
| ctext-C3 | grype-file | commons-text:1.9 → no | CVE-2022-42889 | no | 0/2 | 0 | 0 | app:app:1.0.0 | 3.61 |
| ctext-C3 | osv-scanner | commons-text:1.9 → no | CVE-2022-42889 | no | 0/2 | 0 | 0 | app:app:1.0.0 | 0.77 |
| ctext-C4 | trivy | commons-text:1.9 → no | CVE-2022-42889 | no | 0/2 | 0 | 0 | io.zeebe.zeeqs:app:1.0.0 | 0.7 |
| ctext-C4 | syft | commons-text:1.9 → no | CVE-2022-42889 | – | 0/2 | – | – | app:app:1.0.0 | 1.26 |
| ctext-C4 | grype-sbom | commons-text:1.9 → no | CVE-2022-42889 | no | 0/2 | 0 | 0 | app:app:1.0.0 | 3.69 |
| ctext-C4 | grype-file | commons-text:1.9 → no | CVE-2022-42889 | no | 0/2 | 0 | 0 | app:app:1.0.0 | 3.75 |
| ctext-C4 | osv-scanner | commons-text:1.9 → no | CVE-2022-42889 | no | 0/2 | 0 | 0 | app:app:1.0.0 | 0.74 |
| grpc-real | trivy | netty-codec-http2:4.1.52.Final → no | CVE-2021-21409 | no | 0/14 | 1 | 0 | 0 | 0.66 |
| grpc-real | syft | netty-codec-http2:4.1.52.Final → no | CVE-2021-21409 | – | 0/14 | – | – | grpc-netty-shaded:grpc-netty-shaded:1.40.1 | 1.5 |
| grpc-real | grype-sbom | netty-codec-http2:4.1.52.Final → no | CVE-2021-21409 | no | 0/14 | 0 | 0 | grpc-netty-shaded:grpc-netty-shaded:1.40.1 | 3.59 |
| grpc-real | grype-file | netty-codec-http2:4.1.52.Final → no | CVE-2021-21409 | no | 0/14 | 0 | 0 | grpc-netty-shaded:grpc-netty-shaded:1.40.1 | 3.71 |
| grpc-real | osv-scanner | netty-codec-http2:4.1.52.Final → no | CVE-2021-21409 | no | 0/14 | 0 | 0 | grpc-netty-shaded:grpc-netty-shaded:1.40.1 | 0.79 |
| hadoop-real | trivy | jackson-databind:2.10.5.1 → name and version | CVE-2020-36518 | yes | 84/85 | 58 | 0 | 0 | 0.47 |
| hadoop-real | trivy | snappy-java:1.1.8.2 → no | CVE-2023-34453 | no | 84/85 | 58 | 0 | 0 | 0.47 |
| hadoop-real | syft | jackson-databind:2.10.5.1 → name and version | CVE-2020-36518 | – | 84/85 | – | – | org.apache.hadoop.thirdparty:hadoop-client-runtime:3.3.1 | 1.84 |
| hadoop-real | syft | snappy-java:1.1.8.2 → no | CVE-2023-34453 | – | 84/85 | – | – | org.apache.hadoop.thirdparty:hadoop-client-runtime:3.3.1 | 1.84 |
| hadoop-real | grype-sbom | jackson-databind:2.10.5.1 → name and version | CVE-2020-36518 | yes | 84/85 | 58 | 0 | org.apache.hadoop.thirdparty:hadoop-client-runtime:3.3.1 | 3.87 |
| hadoop-real | grype-sbom | snappy-java:1.1.8.2 → no | CVE-2023-34453 | no | 84/85 | 58 | 0 | org.apache.hadoop.thirdparty:hadoop-client-runtime:3.3.1 | 3.87 |
| hadoop-real | grype-file | jackson-databind:2.10.5.1 → name and version | CVE-2020-36518 | yes | 84/85 | 58 | 0 | org.apache.hadoop.thirdparty:hadoop-client-runtime:3.3.1 | 4.16 |
| hadoop-real | grype-file | snappy-java:1.1.8.2 → no | CVE-2023-34453 | no | 84/85 | 58 | 0 | org.apache.hadoop.thirdparty:hadoop-client-runtime:3.3.1 | 4.16 |
| hadoop-real | osv-scanner | jackson-databind:2.10.5.1 → name and version | CVE-2020-36518 | yes | 84/85 | 58 | 0 | 0 | 1.6 |
| hadoop-real | osv-scanner | snappy-java:1.1.8.2 → no | CVE-2023-34453 | no | 84/85 | 58 | 0 | 0 | 1.6 |
| log4j-C0 | trivy | log4j-core:2.14.1 → name and version | CVE-2021-44228 | yes | 1/1 | 8 | 0 | 0 | 0.4 |
| log4j-C0 | syft | log4j-core:2.14.1 → name and version | CVE-2021-44228 | – | 1/1 | – | – | 0 | 1.29 |
| log4j-C0 | grype-sbom | log4j-core:2.14.1 → name and version | CVE-2021-44228 | yes | 1/1 | 8 | 0 | 0 | 3.62 |
| log4j-C0 | grype-file | log4j-core:2.14.1 → name and version | CVE-2021-44228 | yes | 1/1 | 8 | 0 | 0 | 3.62 |
| log4j-C0 | osv-scanner | log4j-core:2.14.1 → name and version | CVE-2021-44228 | yes | 1/1 | 8 | 0 | 0 | 1.08 |
| log4j-C1 | trivy | log4j-core:2.14.1 → name and version | CVE-2021-44228 | yes | 2/2 | 9 | 0 | io.zeebe.zeeqs:app:1.0.0 | 0.42 |
| log4j-C1 | syft | log4j-core:2.14.1 → name and version | CVE-2021-44228 | – | 2/2 | – | – | app:app:1.0.0 | 1.52 |
| log4j-C1 | grype-sbom | log4j-core:2.14.1 → name and version | CVE-2021-44228 | yes | 2/2 | 9 | 0 | app:app:1.0.0 | 3.61 |
| log4j-C1 | grype-file | log4j-core:2.14.1 → name and version | CVE-2021-44228 | yes | 2/2 | 9 | 0 | app:app:1.0.0 | 3.76 |
| log4j-C1 | osv-scanner | log4j-core:2.14.1 → name and version | CVE-2021-44228 | yes | 2/2 | 9 | 0 | 0 | 1.12 |
| log4j-C2 | trivy | log4j-core:2.14.1 → name and version | CVE-2021-44228 | yes | 2/2 | 9 | 0 | io.zeebe.zeeqs:app:1.0.0 | 0.5 |
| log4j-C2 | syft | log4j-core:2.14.1 → name and version | CVE-2021-44228 | – | 2/2 | – | – | app:app:1.0.0 | 1.29 |
| log4j-C2 | grype-sbom | log4j-core:2.14.1 → name and version | CVE-2021-44228 | yes | 2/2 | 9 | 0 | app:app:1.0.0 | 3.64 |
| log4j-C2 | grype-file | log4j-core:2.14.1 → name and version | CVE-2021-44228 | yes | 2/2 | 9 | 0 | app:app:1.0.0 | 3.63 |
| log4j-C2 | osv-scanner | log4j-core:2.14.1 → name and version | CVE-2021-44228 | yes | 2/2 | 9 | 0 | 0 | 1.19 |
| log4j-C3 | trivy | log4j-core:2.14.1 → no | CVE-2021-44228 | no | 0/2 | 0 | 0 | io.zeebe.zeeqs:app:1.0.0 | 0.69 |
| log4j-C3 | syft | log4j-core:2.14.1 → no | CVE-2021-44228 | – | 0/2 | – | – | app:app:1.0.0 | 1.4 |
| log4j-C3 | grype-sbom | log4j-core:2.14.1 → no | CVE-2021-44228 | no | 0/2 | 0 | 0 | app:app:1.0.0 | 3.91 |
| log4j-C3 | grype-file | log4j-core:2.14.1 → no | CVE-2021-44228 | no | 0/2 | 0 | 0 | app:app:1.0.0 | 3.89 |
| log4j-C3 | osv-scanner | log4j-core:2.14.1 → no | CVE-2021-44228 | no | 0/2 | 0 | 0 | app:app:1.0.0 | 0.79 |
| log4j-C4 | trivy | log4j-core:2.14.1 → no | CVE-2021-44228 | no | 0/2 | 0 | 0 | io.zeebe.zeeqs:app:1.0.0 | 0.73 |
| log4j-C4 | syft | log4j-core:2.14.1 → no | CVE-2021-44228 | – | 0/2 | – | – | app:app:1.0.0 | 1.32 |
| log4j-C4 | grype-sbom | log4j-core:2.14.1 → no | CVE-2021-44228 | no | 0/2 | 0 | 0 | app:app:1.0.0 | 3.64 |
| log4j-C4 | grype-file | log4j-core:2.14.1 → no | CVE-2021-44228 | no | 0/2 | 0 | 0 | app:app:1.0.0 | 3.9 |
| log4j-C4 | osv-scanner | log4j-core:2.14.1 → no | CVE-2021-44228 | no | 0/2 | 0 | 0 | app:app:1.0.0 | 0.72 |

#### Columns

- Inserted library: kľúčová knižnica prípadu a či ju nástroj uviedol medzi komponentmi.
- Components found/inserted: vložené knižnice nájdené so správnym menom aj verziou (syntetické: knižnica + tranzitívna závislosť; hadoop: 84 s pom.properties + snappy-java bez metadát; grpc: 12 modulov Netty, netty-tcnative, grpc-netty).
- Findings: pairs package × vulnerability.
- False findings: a package missing in the artifact (different name, group or version).
- False components: identified components missing in the artifact.
- Time: the whole `docker run` including the container start, databases pre-downloaded; OSV-Scanner calls online API.
- Syft does not search for vulnerabilities (–). grype-sbom uses SBOM from Syftu, grype-file is scanning the file directly.

#### Environment

```
date_utc: 2026-11-02T02:09:46Z
host: Darwin arm64
docker: 29.6.2
java: java version "21.0.4" 2024-07-16 LTS
maven: Apache Maven 3.9.9 (8e8579a9e76f7d015ee5ec7bfcdc97d260186937)
maven-shade-plugin: 3.6.0
image aquasec/trivy:latest: aquasec/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c
image anchore/syft:latest: anchore/syft@sha256:4cc92b64ca74ffca4c94d4c8fcc01f217731375300be14d0b6eeb2e82eaa110a
image anchore/grype:latest: anchore/grype@sha256:621d56d1d68106b787022c81546f7e0a36202a25d1239f0c20195fab8c16f7ea
image ghcr.io/google/osv-scanner:latest: ghcr.io/google/osv-scanner@sha256:4f3b7e2c64b9d38a5febc5a7e4a3dfef1d1362f726dea7a2ef4762b46469fcd0
--- trivy version
{"Version":"0.76.1","VulnerabilityDB":{"Version":2,"NextUpdate":"2026-11-03T01:14:05.64063672Z","UpdatedAt":"2026-11-02T01:14:05.640637121Z","DownloadedAt":"2026-11-02T01:58:54.730233586Z"},"JavaDB":{"Version":1,"NextUpdate":"2026-11-05T01:21:00.147682798Z","UpdatedAt":"2026-11-02T01:21:00.147683029Z","DownloadedAt":"2026-11-02T01:59:28.62370388Z"}}

--- syft version
Application:   syft
Version:       1.55.0
BuildDate:     2026-10-19T18:54:46Z
GitCommit:     f15c3343e29dfb20cf6d82c820e7090b49808c96
GitDescription: v1.55.0
Platform:      linux/arm64
GoVersion:     go1.26.8
Compiler:      gc
SchemaVersion: 16.1.11
--- grype version
Application:         grype
Version:             0.121.0
BuildDate:           2026-10-19T20:26:34Z
GitCommit:           afe2742527d98d822da06c9f32eed86fe3d193e0
GitDescription:      v0.121.0
Platform:            linux/arm64
GoVersion:           go1.26.8
Compiler:            gc
Syft Version:        v1.55.0
Supported DB Schema: 6
--- grype db status
Path:      /cache/6/vulnerability.db
Schema:    v6.1.10
Built:     2026-11-01T06:20:12Z
From:      https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.10_2026-11-01T00:24:34Z_1793514012.tar.zst?checksum=sha256%3Ad0e1af9e6491440e1a671d0a0aafc32c5c7cb5cda787dcec3482799ef298f31c
Status:    valid
--- osv-scanner version
osv-scanner version: 2.7.0
osv-scalibr version: 0.5.3
commit: bfe2f84abd2f09fe0b83ba7f6dad40d296762f40
built at: 2026-10-12T00:39:39Z
osv-scanner db: online API osv.dev v čase behu (bez lokálnej databázy)
```
