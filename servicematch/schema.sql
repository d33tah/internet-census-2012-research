#!/bin/sh

psql -a << END-OF-FILE

\set ON_ERROR_STOP ON

DROP TABLE IF EXISTS service_probe;
DROP TABLE IF EXISTS service_probe_fingerprint;

CREATE TABLE service_probe_fingerprint (
  fingerprint_md5 CHAR(32)      PRIMARY KEY,
  fingerprint     VARCHAR(4500) NOT NULL
);

CREATE TABLE service_probe (
  ip              INET        NOT NULL,
  portno          INTEGER     NOT NULL,
  is_tcp          CHAR(1)     NOT NULL,
  time_taken      TIMESTAMP   NOT NULL,
  statuscode      CHAR(1)     NOT NULL,
  probe           VARCHAR(17) NOT NULL,
  fingerprint_md5 CHAR(32)    NOT NULL
);

CREATE INDEX service_probe__ip ON service_probe(ip);
CREATE INDEX service_probe__fingerprint_md5 ON service_probe(fingerprint_md5);

CREATE OR REPLACE FUNCTION insert_fingerprint(
  ip              INET,
  portno          INTEGER,
  is_tcp          INTEGER,
  time_taken      INTEGER,
  statuscode      INTEGER,
  probe           TEXT,
  fingerprint     TEXT
)
RETURNS void AS
\$body\$
BEGIN
    INSERT INTO service_probe (
      ip,
      portno,
      is_tcp,
      time_taken,
      statuscode,
      probe,
      fingerprint_md5
    ) VALUES
      (\$1,
        \$2,
        \$3,
        abstime(\$4),
        \$5,
        \$6,
        md5(\$6))
    ;

BEGIN
    INSERT INTO service_probe_fingerprint (
      fingerprint_md5,
      fingerprint
    ) VALUES
      (md5(\$6),
        \$6
      )
    ;

EXCEPTION
    WHEN unique_violation
    THEN NULL;
END;
END;
\$body\$
LANGUAGE plpgsql;

SELECT insert_fingerprint(inet '111.4.115.13',
    61613,
    1,
    1346809500,
    1,
    'DNSVersionBindReq',
    '=15=03=01=00=02=02=0A');

SELECT insert_fingerprint(inet '111.4.115.14',
    61613,
    1,
    1346809500,
    1,
    'DNSVersionBindReq',
    '=15=03=01=00=02=02=0A');



SELECT * FROM service_probe;

EXPLAIN ANALYZE SELECT * FROM service_probe WHERE ip='127.0.0.1';
EXPLAIN ANALYZE SELECT * FROM service_probe WHERE fingerprint_md5=md5('=15=03=01=00=02=02=0A');

TRUNCATE service_probe;
TRUNCATE service_probe_fingerprint;

END-OF-FILE
