"""Fixed PostgreSQL 17 catalog query. No caller SQL or object-name interpolation."""


def fingerprint(expression: str) -> str:
    return f"encode(sha256(convert_to(({expression})::text, 'UTF8')), 'hex')"


def member(catalog: str, oid: str) -> str:
    return (
        "EXISTS (SELECT 1 FROM pg_depend d WHERE d.deptype='e' "
        f"AND d.classid='{catalog}'::regclass AND d.objid={oid})"
    )


# OIDs are used only for joins, never emitted as portable identity.
CATALOG_SQL = """
WITH ns AS (
 SELECT oid, nspname FROM pg_namespace
 WHERE nspname NOT LIKE 'pg\\_%' ESCAPE '\\' AND nspname <> 'information_schema'
), rel AS (
 SELECT c.*, n.nspname FROM pg_class c JOIN ns n ON n.oid=c.relnamespace
 WHERE NOT MEMBER_REL
), objects AS (
 SELECT 'SCHEMA' AS kind, jsonb_build_array(nspname) AS key,
        jsonb_build_object() AS facts FROM ns
 UNION ALL
 SELECT CASE relkind WHEN 'r' THEN 'TABLE' WHEN 'p' THEN 'TABLE'
        WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED_VIEW' ELSE 'UNSUPPORTED' END,
        jsonb_build_array(nspname, relname),
        CASE WHEN relkind IN ('v','m') THEN
          jsonb_build_object('definition_hash', HASH_VIEW, 'options', reloptions)
        ELSE jsonb_build_object('persistence', relpersistence, 'partitioned',
          relkind='p' OR relispartition, 'kind', relkind,
          'inherits', EXISTS (SELECT 1 FROM pg_inherits i WHERE i.inhrelid=rel.oid)) END
 FROM rel WHERE relkind IN ('r','p','v','m','f','c')
 UNION ALL
 SELECT 'COLUMN', jsonb_build_array(r.nspname, r.relname, a.attname),
   jsonb_build_object('ordinal', a.attnum, 'data_type', format_type(a.atttypid,a.atttypmod),
     'ordinary_table', r.relkind='r' AND NOT r.relispartition AND NOT EXISTS
       (SELECT 1 FROM pg_inherits inh WHERE inh.inhrelid=r.oid),
     'type_schema', tn.nspname, 'type_name', t.typname,
     'nullable', NOT a.attnotnull AND NOT t.typnotnull,
     'default_hash', HASH_DEFAULT, 'identity', a.attidentity, 'generated', a.attgenerated,
     'collation', CASE WHEN a.attcollation<>0 THEN
       jsonb_build_array(cn.nspname, co.collname) ELSE NULL END)
 FROM rel r JOIN pg_attribute a ON a.attrelid=r.oid
 JOIN pg_type t ON t.oid=a.atttypid JOIN pg_namespace tn ON tn.oid=t.typnamespace
 LEFT JOIN pg_attrdef ad ON ad.adrelid=r.oid AND ad.adnum=a.attnum
 LEFT JOIN pg_collation co ON co.oid=a.attcollation
 LEFT JOIN pg_namespace cn ON cn.oid=co.collnamespace
 WHERE a.attnum>0 AND NOT a.attisdropped AND r.relkind IN ('r','p','v','m')
 UNION ALL
 SELECT 'CONSTRAINT', jsonb_build_array(r.nspname,r.relname,c.conname),
   jsonb_build_object('type', c.contype, 'definition_hash', HASH_CONSTRAINT,
     'validated', c.convalidated, 'deferrable', c.condeferrable, 'deferred', c.condeferred)
 FROM pg_constraint c JOIN rel r ON r.oid=c.conrelid WHERE NOT MEMBER_CONSTRAINT
 UNION ALL
 SELECT 'INDEX', jsonb_build_array(r.nspname,r.relname,ic.relname),
   jsonb_build_object('unique', i.indisunique, 'primary', i.indisprimary,
     'valid', i.indisvalid, 'ready', i.indisready, 'definition_hash', HASH_INDEX,
     'predicate_hash', HASH_PREDICATE,
     'constraint_backed', EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conindid=i.indexrelid))
 FROM pg_index i JOIN rel r ON r.oid=i.indrelid JOIN pg_class ic ON ic.oid=i.indexrelid
 WHERE NOT MEMBER_INDEX
 UNION ALL
 SELECT 'FUNCTION', jsonb_build_array(n.nspname,p.proname,
     pg_get_function_identity_arguments(p.oid)),
   jsonb_build_object('returns', pg_get_function_result(p.oid), 'language', l.lanname,
     'kind', p.prokind, 'definition_hash', CASE WHEN p.prokind IN ('f','p')
        THEN HASH_FUNCTION ELSE NULL END)
 FROM pg_proc p JOIN ns n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang
 WHERE NOT MEMBER_FUNCTION
 UNION ALL
 SELECT 'RLS', jsonb_build_array(nspname,relname),
   jsonb_build_object('enabled',relrowsecurity,'forced',relforcerowsecurity)
 FROM rel WHERE relkind IN ('r','p')
 UNION ALL
 SELECT 'POLICY', jsonb_build_array(r.nspname,r.relname,p.polname),
   jsonb_build_object('command',p.polcmd,'permissive',p.polpermissive,
     'roles',(SELECT jsonb_agg(role ORDER BY role COLLATE "C") FROM
       (SELECT CASE WHEN x=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x) END AS role
        FROM unnest(p.polroles) x) roles),
     'using_hash', HASH_USING, 'check_hash', HASH_CHECK)
 FROM pg_policy p JOIN rel r ON r.oid=p.polrelid
 UNION ALL
 SELECT 'ENUM', jsonb_build_array(n.nspname,t.typname),
   jsonb_build_object('labels_hash',HASH_ENUM,'label_count',
      (SELECT count(*) FROM pg_enum e WHERE e.enumtypid=t.oid))
 FROM pg_type t JOIN ns n ON n.oid=t.typnamespace WHERE t.typtype='e' AND NOT MEMBER_TYPE
 UNION ALL
 SELECT 'SEQUENCE', jsonb_build_array(r.nspname,r.relname),
   jsonb_build_object('type',format_type(s.seqtypid,NULL),'start',s.seqstart,
     'increment',s.seqincrement,'min',s.seqmin,'max',s.seqmax,'cache',s.seqcache,
     'cycle',s.seqcycle,'owned_by',(SELECT jsonb_build_array(n.nspname,c.relname,a.attname)
       FROM pg_depend d JOIN pg_class c ON c.oid=d.refobjid
       JOIN pg_namespace n ON n.oid=c.relnamespace
       JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=d.refobjsubid
       WHERE d.classid='pg_class'::regclass AND d.objid=r.oid AND d.deptype IN ('a','i')
       AND d.refclassid='pg_class'::regclass))
 FROM pg_sequence s JOIN rel r ON r.oid=s.seqrelid
 UNION ALL
 SELECT 'TRIGGER',jsonb_build_array(r.nspname,r.relname,t.tgname),
   jsonb_build_object('enabled',t.tgenabled,'definition_hash',HASH_TRIGGER)
 FROM pg_trigger t JOIN rel r ON r.oid=t.tgrelid WHERE NOT t.tgisinternal AND NOT MEMBER_TRIGGER
 UNION ALL
 SELECT 'EXTENSION',jsonb_build_array(e.extname),
   jsonb_build_object('version',e.extversion,'namespace',n.nspname)
 FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace
 UNION ALL
 SELECT 'UNSUPPORTED',jsonb_build_array(n.nspname,t.typname,'type'),
   jsonb_build_object('kind',t.typtype)
 FROM pg_type t JOIN ns n ON n.oid=t.typnamespace
 WHERE t.typtype IN ('d','r','m','b') AND t.typelem=0 AND NOT MEMBER_TYPE
 UNION ALL
 SELECT 'UNSUPPORTED',jsonb_build_array(r.nspname,r.relname,w.rulename,'rule'),
   jsonb_build_object('kind','rewrite_rule')
 FROM pg_rewrite w JOIN rel r ON r.oid=w.ev_class WHERE w.rulename <> '_RETURN'
)
SELECT jsonb_build_object('server_major',current_setting('server_version_num')::int / 10000,
 'namespaces',(SELECT jsonb_agg(nspname ORDER BY nspname COLLATE "C") FROM pg_namespace),
 'objects',COALESCE((SELECT jsonb_agg(jsonb_build_object('kind',kind,'key',key,'facts',facts)
 ORDER BY kind COLLATE "C",key::text COLLATE "C") FROM objects),'[]'::jsonb));
"""
for token, expression in {
    "HASH_VIEW": "pg_get_viewdef(rel.oid,false)",
    "HASH_DEFAULT": "pg_get_expr(ad.adbin,ad.adrelid,false)",
    "HASH_CONSTRAINT": "pg_get_constraintdef(c.oid,false)",
    "HASH_INDEX": "pg_get_indexdef(i.indexrelid,0,false)",
    "HASH_PREDICATE": "pg_get_expr(i.indpred,i.indrelid,false)",
    "HASH_FUNCTION": "pg_get_functiondef(p.oid)",
    "HASH_USING": "pg_get_expr(p.polqual,p.polrelid,false)",
    "HASH_CHECK": "pg_get_expr(p.polwithcheck,p.polrelid,false)",
    "HASH_ENUM": "(SELECT jsonb_agg(e.enumlabel ORDER BY e.enumsortorder) "
    "FROM pg_enum e WHERE e.enumtypid=t.oid)",
    "HASH_TRIGGER": "pg_get_triggerdef(t.oid,false)",
}.items():
    CATALOG_SQL = CATALOG_SQL.replace(token, fingerprint(expression))
for token, catalog, oid in (
    ("MEMBER_REL", "pg_class", "c.oid"),
    ("MEMBER_CONSTRAINT", "pg_constraint", "c.oid"),
    ("MEMBER_INDEX", "pg_class", "ic.oid"),
    ("MEMBER_FUNCTION", "pg_proc", "p.oid"),
    ("MEMBER_TYPE", "pg_type", "t.oid"),
    ("MEMBER_TRIGGER", "pg_trigger", "t.oid"),
):
    CATALOG_SQL = CATALOG_SQL.replace(token, member(catalog, oid))

READ_SQL = (
    "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; "
    "SET LOCAL search_path=pg_catalog; SET LOCAL statement_timeout='15s'; "
    "SET LOCAL lock_timeout='2s'; " + CATALOG_SQL + " ROLLBACK;"
)
