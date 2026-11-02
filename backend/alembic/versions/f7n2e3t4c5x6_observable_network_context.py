"""observables: network context columns.

asn, asn_org and geo_country (Team Cymru, VirusTotal), registered_at (RDAP),
popularity_rank (Tranco, indexed for the daily match) and noise_class
(GreyNoise). Each is the one home of its fact: the values VirusTotal and
GreyNoise kept in ``reputation`` (asn, as_owner, country, gn_classification)
move into the columns and leave the JSON; a value no column can hold stays. GreyNoise's stored context key
``classification`` becomes ``noise_class``, the key its column reads.

Revision ID: f7n2e3t4c5x6
Revises: w1k2d3a4e5o6
"""

import sqlalchemy as sa

from alembic import op

revision = "f7n2e3t4c5x6"
down_revision = "w1k2d3a4e5o6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("observables", sa.Column("asn", sa.Integer(), nullable=True))
    op.add_column("observables", sa.Column("asn_org", sa.Text(), nullable=True))
    op.add_column("observables", sa.Column("geo_country", sa.String(2), nullable=True))
    op.add_column("observables", sa.Column("registered_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("observables", sa.Column("popularity_rank", sa.Integer(), nullable=True))
    op.add_column("observables", sa.Column("noise_class", sa.String(16), nullable=True))
    op.create_index("ix_observables_popularity_rank", "observables", ["popularity_rank"])

    # A value moves only when its column can hold it; a key whose value didn't
    # move (a malformed country, GreyNoise's "suspicious", an ASN past int4)
    # stays in the JSON.
    moves = {
        "asn": "reputation->>'asn' ~ '^[0-9]{1,9}$'",
        "as_owner": "btrim(reputation->>'as_owner') <> ''",
        "country": "reputation->>'country' ~ '^[A-Za-z]{2}$'",
        "gn_classification": "reputation->>'gn_classification' IN ('malicious', 'benign', 'unknown')",
    }
    moved = ", ".join(f"CASE WHEN {cond} THEN '{key}' END" for key, cond in moves.items())
    op.execute(
        f"""
        UPDATE observables SET
            asn = CASE WHEN {moves["asn"]} THEN (reputation->>'asn')::int END,
            asn_org = CASE WHEN {moves["as_owner"]} THEN btrim(reputation->>'as_owner') END,
            geo_country = CASE WHEN {moves["country"]} THEN upper(reputation->>'country') END,
            noise_class = CASE WHEN {moves["gn_classification"]} THEN reputation->>'gn_classification' END,
            reputation = reputation - array_remove(ARRAY[{moved}], NULL)
        WHERE reputation ?| array['asn', 'as_owner', 'country', 'gn_classification']
        """
    )
    op.execute(
        "UPDATE entity_context SET key = 'noise_class' WHERE source_type = 'greynoise' AND key = 'classification'"
    )


def downgrade() -> None:
    op.execute(
        "UPDATE entity_context SET key = 'classification' WHERE source_type = 'greynoise' AND key = 'noise_class'"
    )
    op.execute(
        """
        UPDATE observables SET reputation = coalesce(reputation, '{}'::jsonb) || jsonb_strip_nulls(
            jsonb_build_object(
                'asn', asn, 'as_owner', asn_org, 'country', geo_country,
                'gn_classification', CASE WHEN noise_class <> 'not_seen' THEN noise_class END
            )
        )
        WHERE asn IS NOT NULL OR asn_org IS NOT NULL OR geo_country IS NOT NULL OR noise_class IS NOT NULL
        """
    )
    op.drop_index("ix_observables_popularity_rank", table_name="observables")
    for column in ("noise_class", "popularity_rank", "registered_at", "geo_country", "asn_org", "asn"):
        op.drop_column("observables", column)
