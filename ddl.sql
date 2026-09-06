CREATE OR REPLACE FUNCTION tags_to_tagvalues(jsonb) RETURNS text[]
    AS 'SELECT array_agg(t->>1) FROM (SELECT jsonb_array_elements($1) AS t)s WHERE length(t->>0) = 1;'
    LANGUAGE SQL
    IMMUTABLE
    RETURNS NULL ON NULL INPUT;

CREATE TABLE IF NOT EXISTS event (
  id text NOT NULL,
  pubkey text NOT NULL,
  created_at integer NOT NULL,
  kind integer NOT NULL,
  tags jsonb NOT NULL,
  content text NOT NULL,
  sig text NOT NULL,

  tagvalues text[] GENERATED ALWAYS AS (tags_to_tagvalues(tags)) STORED
);

CREATE UNIQUE INDEX IF NOT EXISTS ididx ON event USING btree (id text_pattern_ops);
CREATE INDEX IF NOT EXISTS pubkeyprefix ON event USING btree (pubkey text_pattern_ops);
CREATE INDEX IF NOT EXISTS timeidx ON event (created_at DESC);
CREATE INDEX IF NOT EXISTS kindidx ON event (kind);
CREATE INDEX IF NOT EXISTS kindtimeidx ON event(kind,created_at DESC);
CREATE INDEX IF NOT EXISTS arbitrarytagvalues ON event USING gin (tagvalues);

-- NIP-50: accelerate substring search (ILIKE '%...%') on content. A pg_trgm
-- trigram GIN index avoids a sequential scan even with a leading wildcard.
-- Terms shorter than 3 characters produce no trigrams and still fall back to
-- a scan.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS contenttrgmidx ON event USING gin (content gin_trgm_ops);

