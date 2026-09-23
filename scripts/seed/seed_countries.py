"""Seed the countries table with all UN-recognized countries.

Run inside the api container:
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_countries.py
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_countries.py --dry-run

Only seeds an empty table; if countries already exist it reports and exits.
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import func, select

from app.database import async_session
from app.models.country import Country

# (name, iso_code, region, aliases)
COUNTRIES = [
    # Africa
    ("Algeria", "DZ", "Africa", ["People's Democratic Republic of Algeria"]),
    ("Angola", "AO", "Africa", []),
    ("Benin", "BJ", "Africa", []),
    ("Botswana", "BW", "Africa", []),
    ("Burkina Faso", "BF", "Africa", []),
    ("Burundi", "BI", "Africa", []),
    ("Cabo Verde", "CV", "Africa", ["Cape Verde"]),
    ("Cameroon", "CM", "Africa", []),
    ("Central African Republic", "CF", "Africa", ["CAR"]),
    ("Chad", "TD", "Africa", []),
    ("Comoros", "KM", "Africa", []),
    ("Congo", "CG", "Africa", ["Republic of the Congo", "Congo-Brazzaville"]),
    ("Democratic Republic of the Congo", "CD", "Africa", ["DRC", "Congo-Kinshasa"]),
    ("Djibouti", "DJ", "Africa", []),
    ("Egypt", "EG", "Africa", []),
    ("Equatorial Guinea", "GQ", "Africa", []),
    ("Eritrea", "ER", "Africa", []),
    ("Eswatini", "SZ", "Africa", ["Swaziland"]),
    ("Ethiopia", "ET", "Africa", []),
    ("Gabon", "GA", "Africa", []),
    ("Gambia", "GM", "Africa", ["The Gambia"]),
    ("Ghana", "GH", "Africa", []),
    ("Guinea", "GN", "Africa", []),
    ("Guinea-Bissau", "GW", "Africa", []),
    ("Ivory Coast", "CI", "Africa", ["Cote d'Ivoire", "Cote d Ivoire"]),
    ("Kenya", "KE", "Africa", []),
    ("Lesotho", "LS", "Africa", []),
    ("Liberia", "LR", "Africa", []),
    ("Libya", "LY", "Africa", []),
    ("Madagascar", "MG", "Africa", []),
    ("Malawi", "MW", "Africa", []),
    ("Mali", "ML", "Africa", []),
    ("Mauritania", "MR", "Africa", []),
    ("Mauritius", "MU", "Africa", []),
    ("Morocco", "MA", "Africa", []),
    ("Mozambique", "MZ", "Africa", []),
    ("Namibia", "NA", "Africa", []),
    ("Niger", "NE", "Africa", []),
    ("Nigeria", "NG", "Africa", []),
    ("Rwanda", "RW", "Africa", []),
    ("Sao Tome and Principe", "ST", "Africa", []),
    ("Senegal", "SN", "Africa", []),
    ("Seychelles", "SC", "Africa", []),
    ("Sierra Leone", "SL", "Africa", []),
    ("Somalia", "SO", "Africa", []),
    ("South Africa", "ZA", "Africa", []),
    ("South Sudan", "SS", "Africa", []),
    ("Sudan", "SD", "Africa", []),
    ("Tanzania", "TZ", "Africa", ["United Republic of Tanzania"]),
    ("Togo", "TG", "Africa", []),
    ("Tunisia", "TN", "Africa", []),
    ("Uganda", "UG", "Africa", []),
    ("Zambia", "ZM", "Africa", []),
    ("Zimbabwe", "ZW", "Africa", []),
    # Asia
    ("Afghanistan", "AF", "Asia", []),
    ("Armenia", "AM", "Asia", []),
    ("Azerbaijan", "AZ", "Asia", []),
    ("Bahrain", "BH", "Asia", []),
    ("Bangladesh", "BD", "Asia", []),
    ("Bhutan", "BT", "Asia", []),
    ("Brunei", "BN", "Asia", ["Brunei Darussalam"]),
    ("Cambodia", "KH", "Asia", []),
    ("China", "CN", "Asia", ["People's Republic of China", "PRC"]),
    ("Cyprus", "CY", "Asia", []),
    ("Georgia", "GE", "Asia", []),
    ("India", "IN", "Asia", []),
    ("Indonesia", "ID", "Asia", []),
    ("Iran", "IR", "Asia", ["Islamic Republic of Iran", "Persia"]),
    ("Iraq", "IQ", "Asia", []),
    ("Israel", "IL", "Asia", []),
    ("Japan", "JP", "Asia", []),
    ("Jordan", "JO", "Asia", []),
    ("Kazakhstan", "KZ", "Asia", []),
    ("Kuwait", "KW", "Asia", []),
    ("Kyrgyzstan", "KG", "Asia", []),
    ("Laos", "LA", "Asia", ["Lao People's Democratic Republic"]),
    ("Lebanon", "LB", "Asia", []),
    ("Malaysia", "MY", "Asia", []),
    ("Maldives", "MV", "Asia", []),
    ("Mongolia", "MN", "Asia", []),
    ("Myanmar", "MM", "Asia", ["Burma"]),
    ("Nepal", "NP", "Asia", []),
    ("North Korea", "KP", "Asia", ["DPRK", "Democratic People's Republic of Korea"]),
    ("Oman", "OM", "Asia", []),
    ("Pakistan", "PK", "Asia", []),
    ("Palestine", "PS", "Asia", ["State of Palestine"]),
    ("Philippines", "PH", "Asia", []),
    ("Qatar", "QA", "Asia", []),
    ("Saudi Arabia", "SA", "Asia", ["KSA", "Kingdom of Saudi Arabia"]),
    ("Singapore", "SG", "Asia", []),
    ("South Korea", "KR", "Asia", ["Republic of Korea", "ROK"]),
    ("Sri Lanka", "LK", "Asia", []),
    ("Syria", "SY", "Asia", ["Syrian Arab Republic"]),
    ("Taiwan", "TW", "Asia", ["Republic of China", "ROC"]),
    ("Tajikistan", "TJ", "Asia", []),
    ("Thailand", "TH", "Asia", []),
    ("Timor-Leste", "TL", "Asia", ["East Timor"]),
    ("Turkey", "TR", "Asia", ["Turkiye"]),
    ("Turkmenistan", "TM", "Asia", []),
    ("United Arab Emirates", "AE", "Asia", ["UAE"]),
    ("Uzbekistan", "UZ", "Asia", []),
    ("Vietnam", "VN", "Asia", ["Viet Nam"]),
    ("Yemen", "YE", "Asia", []),
    # Europe
    ("Albania", "AL", "Europe", []),
    ("Andorra", "AD", "Europe", []),
    ("Austria", "AT", "Europe", []),
    ("Belarus", "BY", "Europe", []),
    ("Belgium", "BE", "Europe", []),
    ("Bosnia and Herzegovina", "BA", "Europe", []),
    ("Bulgaria", "BG", "Europe", []),
    ("Croatia", "HR", "Europe", []),
    ("Czech Republic", "CZ", "Europe", ["Czechia"]),
    ("Denmark", "DK", "Europe", []),
    ("Estonia", "EE", "Europe", []),
    ("Finland", "FI", "Europe", []),
    ("France", "FR", "Europe", []),
    ("Germany", "DE", "Europe", []),
    ("Greece", "GR", "Europe", []),
    ("Hungary", "HU", "Europe", []),
    ("Iceland", "IS", "Europe", []),
    ("Ireland", "IE", "Europe", []),
    ("Italy", "IT", "Europe", []),
    ("Kosovo", "XK", "Europe", []),
    ("Latvia", "LV", "Europe", []),
    ("Liechtenstein", "LI", "Europe", []),
    ("Lithuania", "LT", "Europe", []),
    ("Luxembourg", "LU", "Europe", []),
    ("Malta", "MT", "Europe", []),
    ("Moldova", "MD", "Europe", ["Republic of Moldova"]),
    ("Monaco", "MC", "Europe", []),
    ("Montenegro", "ME", "Europe", []),
    ("Netherlands", "NL", "Europe", ["Holland"]),
    ("North Macedonia", "MK", "Europe", ["Macedonia"]),
    ("Norway", "NO", "Europe", []),
    ("Poland", "PL", "Europe", []),
    ("Portugal", "PT", "Europe", []),
    ("Romania", "RO", "Europe", []),
    ("Russia", "RU", "Europe", ["Russian Federation"]),
    ("San Marino", "SM", "Europe", []),
    ("Serbia", "RS", "Europe", []),
    ("Slovakia", "SK", "Europe", []),
    ("Slovenia", "SI", "Europe", []),
    ("Spain", "ES", "Europe", []),
    ("Sweden", "SE", "Europe", []),
    ("Switzerland", "CH", "Europe", []),
    ("Ukraine", "UA", "Europe", []),
    ("United Kingdom", "GB", "Europe", ["UK", "Britain", "Great Britain"]),
    ("Vatican City", "VA", "Europe", ["Holy See"]),
    # North America
    ("Antigua and Barbuda", "AG", "North America", []),
    ("Bahamas", "BS", "North America", ["The Bahamas"]),
    ("Barbados", "BB", "North America", []),
    ("Belize", "BZ", "North America", []),
    ("Canada", "CA", "North America", []),
    ("Costa Rica", "CR", "North America", []),
    ("Cuba", "CU", "North America", []),
    ("Dominica", "DM", "North America", []),
    ("Dominican Republic", "DO", "North America", []),
    ("El Salvador", "SV", "North America", []),
    ("Grenada", "GD", "North America", []),
    ("Guatemala", "GT", "North America", []),
    ("Haiti", "HT", "North America", []),
    ("Honduras", "HN", "North America", []),
    ("Jamaica", "JM", "North America", []),
    ("Mexico", "MX", "North America", []),
    ("Nicaragua", "NI", "North America", []),
    ("Panama", "PA", "North America", []),
    ("Saint Kitts and Nevis", "KN", "North America", []),
    ("Saint Lucia", "LC", "North America", []),
    ("Saint Vincent and the Grenadines", "VC", "North America", []),
    ("Trinidad and Tobago", "TT", "North America", []),
    ("United States", "US", "North America", ["USA", "United States of America", "US of A"]),
    # South America
    ("Argentina", "AR", "South America", []),
    ("Bolivia", "BO", "South America", []),
    ("Brazil", "BR", "South America", []),
    ("Chile", "CL", "South America", []),
    ("Colombia", "CO", "South America", []),
    ("Ecuador", "EC", "South America", []),
    ("Guyana", "GY", "South America", []),
    ("Paraguay", "PY", "South America", []),
    ("Peru", "PE", "South America", []),
    ("Suriname", "SR", "South America", []),
    ("Uruguay", "UY", "South America", []),
    ("Venezuela", "VE", "South America", []),
    # Oceania
    ("Australia", "AU", "Oceania", []),
    ("Fiji", "FJ", "Oceania", []),
    ("Kiribati", "KI", "Oceania", []),
    ("Marshall Islands", "MH", "Oceania", []),
    ("Micronesia", "FM", "Oceania", ["Federated States of Micronesia"]),
    ("Nauru", "NR", "Oceania", []),
    ("New Zealand", "NZ", "Oceania", []),
    ("Palau", "PW", "Oceania", []),
    ("Papua New Guinea", "PG", "Oceania", []),
    ("Samoa", "WS", "Oceania", []),
    ("Solomon Islands", "SB", "Oceania", []),
    ("Tonga", "TO", "Oceania", []),
    ("Tuvalu", "TV", "Oceania", []),
    ("Vanuatu", "VU", "Oceania", []),
]


async def main(dry_run: bool) -> None:
    async with async_session() as db:
        existing_count = (await db.execute(select(func.count()).select_from(Country))).scalar() or 0
        if existing_count > 0:
            print(f"Countries table already has {existing_count} rows. Skipping seed.")
            print("To re-seed, truncate the countries table first.")
            return

        created = 0
        for name, iso_code, region, aliases in COUNTRIES:
            country = Country(
                name=name,
                iso_code=iso_code,
                region=region,
                aliases=aliases,
                article_count=0,
            )
            db.add(country)
            created += 1

        if dry_run:
            await db.rollback()
            print(f"Would seed {created} countries. Dry run — nothing written.")
            return

        await db.commit()
        print(f"Seeded {created} countries.")

        # Refresh the autolinker vocabulary so country names are immediately matchable.
        # Skipped on a dry run: it bumps a Redis version that no rollback would undo.
        try:
            from app.intelligence.autolinker import refresh_vocabulary

            count = await refresh_vocabulary(db)
            print(f"Autolinker vocabulary rebuilt: {count} surface forms.")
        except Exception as e:
            print(f"Note: Could not refresh autolinker vocabulary: {e}")
            print("It will refresh automatically on next feed fetch.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Report what would be seeded without writing.")
    asyncio.run(main(parser.parse_args().dry_run))
