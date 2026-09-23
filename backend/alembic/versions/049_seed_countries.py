"""Seed countries with ISO codes, regions, and cyber-relevant aliases.

Revision ID: 049_seed_countries
Revises: 048_country_foundation
Create Date: 2026-03-15
"""

import uuid
from datetime import UTC, datetime

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY, UUID

from alembic import op

revision = "049_seed_countries"
down_revision = "048_country_foundation"
branch_labels = None
depends_on = None

# fmt: off
COUNTRIES = [
    # East Asia
    ("China", "CN", "East Asia", ["PRC", "People's Republic of China", "Chinese"]),
    ("Japan", "JP", "East Asia", ["JPN", "Japanese"]),
    ("South Korea", "KR", "East Asia", ["ROK", "Republic of Korea", "Korean"]),
    ("North Korea", "KP", "East Asia", ["DPRK", "Democratic People's Republic of Korea", "North Korean"]),
    ("Taiwan", "TW", "East Asia", ["ROC", "Republic of China", "Taiwanese"]),
    ("Mongolia", "MN", "East Asia", []),

    # Southeast Asia
    ("Vietnam", "VN", "Southeast Asia", ["Vietnamese"]),
    ("Thailand", "TH", "Southeast Asia", ["Thai"]),
    ("Philippines", "PH", "Southeast Asia", ["Filipino"]),
    ("Indonesia", "ID", "Southeast Asia", ["Indonesian"]),
    ("Malaysia", "MY", "Southeast Asia", ["Malaysian"]),
    ("Singapore", "SG", "Southeast Asia", ["Singaporean"]),
    ("Myanmar", "MM", "Southeast Asia", ["Burma", "Burmese"]),
    ("Cambodia", "KH", "Southeast Asia", ["Cambodian"]),
    ("Laos", "LA", "Southeast Asia", ["Lao", "Laotian"]),
    ("Brunei", "BN", "Southeast Asia", []),
    ("Timor-Leste", "TL", "Southeast Asia", ["East Timor"]),

    # South Asia
    ("India", "IN", "South Asia", ["Indian", "Bharat"]),
    ("Pakistan", "PK", "South Asia", ["Pakistani"]),
    ("Bangladesh", "BD", "South Asia", ["Bangladeshi"]),
    ("Sri Lanka", "LK", "South Asia", ["Sri Lankan"]),
    ("Nepal", "NP", "South Asia", ["Nepalese"]),
    ("Afghanistan", "AF", "South Asia", ["Afghan"]),
    ("Maldives", "MV", "South Asia", []),
    ("Bhutan", "BT", "South Asia", []),

    # Central Asia
    ("Kazakhstan", "KZ", "Central Asia", ["Kazakh"]),
    ("Uzbekistan", "UZ", "Central Asia", ["Uzbek"]),
    ("Turkmenistan", "TM", "Central Asia", ["Turkmen"]),
    ("Kyrgyzstan", "KG", "Central Asia", ["Kyrgyz"]),
    ("Tajikistan", "TJ", "Central Asia", ["Tajik"]),

    # Middle East
    ("Iran", "IR", "Middle East", ["Islamic Republic of Iran", "Iranian", "Persian"]),
    ("Iraq", "IQ", "Middle East", ["Iraqi"]),
    ("Israel", "IL", "Middle East", ["Israeli"]),
    ("Saudi Arabia", "SA", "Middle East", ["KSA", "Kingdom of Saudi Arabia", "Saudi"]),
    ("United Arab Emirates", "AE", "Middle East", ["UAE", "Emirati"]),
    ("Turkey", "TR", "Middle East", ["Turkish", "Türkiye"]),
    ("Syria", "SY", "Middle East", ["Syrian"]),
    ("Lebanon", "LB", "Middle East", ["Lebanese"]),
    ("Jordan", "JO", "Middle East", ["Jordanian"]),
    ("Yemen", "YE", "Middle East", ["Yemeni"]),
    ("Oman", "OM", "Middle East", ["Omani"]),
    ("Kuwait", "KW", "Middle East", ["Kuwaiti"]),
    ("Bahrain", "BH", "Middle East", ["Bahraini"]),
    ("Qatar", "QA", "Middle East", ["Qatari"]),
    ("Palestine", "PS", "Middle East", ["Palestinian", "Gaza", "West Bank"]),
    ("Cyprus", "CY", "Middle East", ["Cypriot"]),

    # Eastern Europe
    ("Russia", "RU", "Eastern Europe", ["Russian Federation", "Russian", "Kremlin", "Moscow"]),
    ("Ukraine", "UA", "Eastern Europe", ["Ukrainian", "Kyiv"]),
    ("Belarus", "BY", "Eastern Europe", ["Belarusian", "Belarussian"]),
    ("Moldova", "MD", "Eastern Europe", ["Moldovan"]),
    ("Georgia", "GE", "Eastern Europe", ["Georgian"]),
    ("Armenia", "AM", "Eastern Europe", ["Armenian"]),
    ("Azerbaijan", "AZ", "Eastern Europe", ["Azerbaijani"]),

    # Northern Europe
    ("United Kingdom", "GB", "Northern Europe", ["UK", "Britain", "Great Britain", "British", "England", "Scotland", "Wales"]),
    ("Ireland", "IE", "Northern Europe", ["Irish", "Eire"]),
    ("Sweden", "SE", "Northern Europe", ["Swedish"]),
    ("Norway", "NO", "Northern Europe", ["Norwegian"]),
    ("Denmark", "DK", "Northern Europe", ["Danish"]),
    ("Finland", "FI", "Northern Europe", ["Finnish"]),
    ("Iceland", "IS", "Northern Europe", ["Icelandic"]),
    ("Estonia", "EE", "Northern Europe", ["Estonian"]),
    ("Latvia", "LV", "Northern Europe", ["Latvian"]),
    ("Lithuania", "LT", "Northern Europe", ["Lithuanian"]),

    # Western Europe
    ("France", "FR", "Western Europe", ["French"]),
    ("Germany", "DE", "Western Europe", ["German", "Deutschland"]),
    ("Netherlands", "NL", "Western Europe", ["Dutch", "Holland"]),
    ("Belgium", "BE", "Western Europe", ["Belgian"]),
    ("Luxembourg", "LU", "Western Europe", []),
    ("Austria", "AT", "Western Europe", ["Austrian"]),
    ("Switzerland", "CH", "Western Europe", ["Swiss"]),
    ("Liechtenstein", "LI", "Western Europe", []),
    ("Monaco", "MC", "Western Europe", []),

    # Southern Europe
    ("Italy", "IT", "Southern Europe", ["Italian"]),
    ("Spain", "ES", "Southern Europe", ["Spanish"]),
    ("Portugal", "PT", "Southern Europe", ["Portuguese"]),
    ("Greece", "GR", "Southern Europe", ["Greek", "Hellenic"]),
    ("Albania", "AL", "Southern Europe", ["Albanian"]),
    ("North Macedonia", "MK", "Southern Europe", ["Macedonian"]),
    ("Serbia", "RS", "Southern Europe", ["Serbian"]),
    ("Montenegro", "ME", "Southern Europe", ["Montenegrin"]),
    ("Bosnia and Herzegovina", "BA", "Southern Europe", ["Bosnian"]),
    ("Croatia", "HR", "Southern Europe", ["Croatian"]),
    ("Slovenia", "SI", "Southern Europe", ["Slovenian"]),
    ("Kosovo", "XK", "Southern Europe", ["Kosovar"]),
    ("Malta", "MT", "Southern Europe", ["Maltese"]),
    ("Andorra", "AD", "Southern Europe", []),
    ("San Marino", "SM", "Southern Europe", []),
    ("Vatican City", "VA", "Southern Europe", ["Holy See"]),

    # Central Europe
    ("Poland", "PL", "Central Europe", ["Polish"]),
    ("Czech Republic", "CZ", "Central Europe", ["Czech", "Czechia"]),
    ("Slovakia", "SK", "Central Europe", ["Slovak"]),
    ("Hungary", "HU", "Central Europe", ["Hungarian"]),
    ("Romania", "RO", "Central Europe", ["Romanian"]),
    ("Bulgaria", "BG", "Central Europe", ["Bulgarian"]),

    # North America
    ("United States", "US", "North America", ["USA", "U.S.", "U.S.A.", "American", "United States of America"]),
    ("Canada", "CA", "North America", ["Canadian"]),
    ("Mexico", "MX", "North America", ["Mexican"]),

    # Central America & Caribbean
    ("Guatemala", "GT", "Central America", []),
    ("Honduras", "HN", "Central America", []),
    ("El Salvador", "SV", "Central America", []),
    ("Nicaragua", "NI", "Central America", []),
    ("Costa Rica", "CR", "Central America", []),
    ("Panama", "PA", "Central America", []),
    ("Belize", "BZ", "Central America", []),
    ("Cuba", "CU", "Caribbean", ["Cuban"]),
    ("Dominican Republic", "DO", "Caribbean", []),
    ("Haiti", "HT", "Caribbean", ["Haitian"]),
    ("Jamaica", "JM", "Caribbean", ["Jamaican"]),
    ("Trinidad and Tobago", "TT", "Caribbean", []),
    ("Bahamas", "BS", "Caribbean", []),
    ("Barbados", "BB", "Caribbean", []),

    # South America
    ("Brazil", "BR", "South America", ["Brazilian"]),
    ("Argentina", "AR", "South America", ["Argentine", "Argentinian"]),
    ("Colombia", "CO", "South America", ["Colombian"]),
    ("Chile", "CL", "South America", ["Chilean"]),
    ("Peru", "PE", "South America", ["Peruvian"]),
    ("Venezuela", "VE", "South America", ["Venezuelan"]),
    ("Ecuador", "EC", "South America", ["Ecuadorian"]),
    ("Bolivia", "BO", "South America", ["Bolivian"]),
    ("Paraguay", "PY", "South America", []),
    ("Uruguay", "UY", "South America", ["Uruguayan"]),
    ("Guyana", "GY", "South America", []),
    ("Suriname", "SR", "South America", []),

    # North Africa
    ("Egypt", "EG", "North Africa", ["Egyptian"]),
    ("Libya", "LY", "North Africa", ["Libyan"]),
    ("Tunisia", "TN", "North Africa", ["Tunisian"]),
    ("Algeria", "DZ", "North Africa", ["Algerian"]),
    ("Morocco", "MA", "North Africa", ["Moroccan"]),
    ("Sudan", "SD", "North Africa", ["Sudanese"]),
    ("South Sudan", "SS", "North Africa", ["South Sudanese"]),

    # West Africa
    ("Nigeria", "NG", "West Africa", ["Nigerian"]),
    ("Ghana", "GH", "West Africa", ["Ghanaian"]),
    ("Senegal", "SN", "West Africa", ["Senegalese"]),
    ("Ivory Coast", "CI", "West Africa", ["Côte d'Ivoire", "Ivorian"]),
    ("Mali", "ML", "West Africa", ["Malian"]),
    ("Burkina Faso", "BF", "West Africa", []),
    ("Niger", "NE", "West Africa", []),
    ("Guinea", "GN", "West Africa", []),
    ("Sierra Leone", "SL", "West Africa", []),
    ("Liberia", "LR", "West Africa", []),
    ("Togo", "TG", "West Africa", []),
    ("Benin", "BJ", "West Africa", []),
    ("Gambia", "GM", "West Africa", []),
    ("Guinea-Bissau", "GW", "West Africa", []),
    ("Mauritania", "MR", "West Africa", []),
    ("Cabo Verde", "CV", "West Africa", ["Cape Verde"]),

    # East Africa
    ("Kenya", "KE", "East Africa", ["Kenyan"]),
    ("Ethiopia", "ET", "East Africa", ["Ethiopian"]),
    ("Tanzania", "TZ", "East Africa", ["Tanzanian"]),
    ("Uganda", "UG", "East Africa", ["Ugandan"]),
    ("Rwanda", "RW", "East Africa", ["Rwandan"]),
    ("Burundi", "BI", "East Africa", []),
    ("Somalia", "SO", "East Africa", ["Somali"]),
    ("Eritrea", "ER", "East Africa", ["Eritrean"]),
    ("Djibouti", "DJ", "East Africa", []),
    ("Madagascar", "MG", "East Africa", ["Malagasy"]),
    ("Mauritius", "MU", "East Africa", []),
    ("Seychelles", "SC", "East Africa", []),
    ("Comoros", "KM", "East Africa", []),

    # Central Africa
    ("Democratic Republic of the Congo", "CD", "Central Africa", ["DRC", "Congo-Kinshasa"]),
    ("Republic of the Congo", "CG", "Central Africa", ["Congo-Brazzaville"]),
    ("Cameroon", "CM", "Central Africa", ["Cameroonian"]),
    ("Central African Republic", "CF", "Central Africa", ["CAR"]),
    ("Chad", "TD", "Central Africa", ["Chadian"]),
    ("Gabon", "GA", "Central Africa", []),
    ("Equatorial Guinea", "GQ", "Central Africa", []),
    ("São Tomé and Príncipe", "ST", "Central Africa", []),

    # Southern Africa
    ("South Africa", "ZA", "Southern Africa", ["South African", "RSA"]),
    ("Namibia", "NA", "Southern Africa", ["Namibian"]),
    ("Botswana", "BW", "Southern Africa", []),
    ("Zimbabwe", "ZW", "Southern Africa", ["Zimbabwean"]),
    ("Mozambique", "MZ", "Southern Africa", ["Mozambican"]),
    ("Zambia", "ZM", "Southern Africa", ["Zambian"]),
    ("Malawi", "MW", "Southern Africa", ["Malawian"]),
    ("Angola", "AO", "Southern Africa", ["Angolan"]),
    ("Lesotho", "LS", "Southern Africa", []),
    ("Eswatini", "SZ", "Southern Africa", ["Swaziland"]),

    # Oceania
    ("Australia", "AU", "Oceania", ["Australian", "Aussie"]),
    ("New Zealand", "NZ", "Oceania", ["Kiwi", "New Zealander"]),
    ("Papua New Guinea", "PG", "Oceania", ["PNG"]),
    ("Fiji", "FJ", "Oceania", ["Fijian"]),
    ("Solomon Islands", "SB", "Oceania", []),
    ("Vanuatu", "VU", "Oceania", []),
    ("Samoa", "WS", "Oceania", []),
    ("Tonga", "TO", "Oceania", []),
    ("Palau", "PW", "Oceania", []),
    ("Micronesia", "FM", "Oceania", []),
    ("Marshall Islands", "MH", "Oceania", []),
    ("Kiribati", "KI", "Oceania", []),
    ("Nauru", "NR", "Oceania", []),
    ("Tuvalu", "TV", "Oceania", []),
]
# fmt: on


def upgrade() -> None:
    now = datetime.now(UTC)
    countries_table = sa.table(
        "countries",
        sa.column("id", UUID(as_uuid=True)),
        sa.column("name", sa.String),
        sa.column("iso_code", sa.String),
        sa.column("region", sa.String),
        sa.column("aliases", ARRAY(sa.Text)),
        sa.column("article_count", sa.Integer),
        sa.column("first_seen_at", sa.DateTime(timezone=True)),
        sa.column("last_seen_at", sa.DateTime(timezone=True)),
        sa.column("metadata_", sa.JSON),
    )

    rows = []
    for name, iso_code, region, aliases in COUNTRIES:
        rows.append(
            {
                "id": str(uuid.uuid4()),
                "name": name,
                "iso_code": iso_code,
                "region": region,
                "aliases": aliases,
                "article_count": 0,
                "first_seen_at": now,
                "last_seen_at": now,
                "metadata_": {},
            }
        )

    # Insert only countries that don't already exist (by name)
    conn = op.get_bind()
    existing = {row[0] for row in conn.execute(sa.text("SELECT name FROM countries")).fetchall()}
    new_rows = [r for r in rows if r["name"] not in existing]
    if new_rows:
        op.bulk_insert(countries_table, new_rows)


def downgrade() -> None:
    # Remove seeded countries that have article_count=0 (never used)
    op.execute("DELETE FROM countries WHERE article_count = 0")
