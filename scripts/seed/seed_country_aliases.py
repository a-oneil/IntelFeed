"""Add demonym and common-name aliases to every seeded country.

The autolinker matches entries against country aliases, so without this an
article that says "Iranian threat actor" never links to Iran. Run it after
seed_countries.py.

Run inside the api container:
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_country_aliases.py
    docker compose -f docker-compose.dev.yml exec api python scripts/seed/seed_country_aliases.py --dry-run

Idempotent: existing aliases are preserved and only missing ones are appended.
"""

import argparse
import asyncio
import sys

sys.path.insert(0, "/app")

from sqlalchemy import select

from app.database import async_session
from app.models.country import Country

# country name → list of aliases to add (demonyms, adjective forms, common abbreviations)
# Existing aliases are preserved; only new ones are appended.
COUNTRY_ALIASES: dict[str, list[str]] = {
    "Afghanistan": ["Afghan", "Afghani"],
    "Albania": ["Albanian"],
    "Algeria": ["Algerian"],
    "Andorra": ["Andorran"],
    "Angola": ["Angolan"],
    "Antigua and Barbuda": ["Antiguan", "Barbudan"],
    "Argentina": ["Argentine", "Argentinian", "Argentinean"],
    "Armenia": ["Armenian"],
    "Australia": ["Australian"],
    "Austria": ["Austrian"],
    "Azerbaijan": ["Azerbaijani", "Azeri"],
    "Bahamas": ["Bahamian"],
    "Bahrain": ["Bahraini"],
    "Bangladesh": ["Bangladeshi"],
    "Barbados": ["Barbadian", "Bajan"],
    "Belarus": ["Belarusian", "Belarussian", "Byelorussian"],
    "Belgium": ["Belgian"],
    "Belize": ["Belizean"],
    "Benin": ["Beninese"],
    "Bhutan": ["Bhutanese"],
    "Bolivia": ["Bolivian"],
    "Bosnia and Herzegovina": ["Bosnian", "Herzegovinian"],
    "Botswana": ["Botswanan", "Motswana"],
    "Brazil": ["Brazilian"],
    "Brunei": ["Bruneian"],
    "Bulgaria": ["Bulgarian"],
    "Burkina Faso": ["Burkinabe"],
    "Burundi": ["Burundian"],
    "Cabo Verde": ["Cape Verdean"],
    "Cambodia": ["Cambodian", "Khmer"],
    "Cameroon": ["Cameroonian"],
    "Canada": ["Canadian"],
    "Central African Republic": ["Central African"],
    "Chad": ["Chadian"],
    "Chile": ["Chilean"],
    "China": ["Chinese", "Sino"],
    "Colombia": ["Colombian"],
    "Comoros": ["Comorian"],
    "Congo": ["Congolese"],
    "Costa Rica": ["Costa Rican", "Tico"],
    "Croatia": ["Croatian", "Croat"],
    "Cuba": ["Cuban"],
    "Cyprus": ["Cypriot"],
    "Czech Republic": ["Czech", "Czechoslovak"],
    "Democratic Republic of the Congo": ["Congolese"],
    "Denmark": ["Danish", "Dane"],
    "Djibouti": ["Djiboutian"],
    "Dominica": ["Dominican"],
    "Dominican Republic": ["Dominican"],
    "Ecuador": ["Ecuadorian", "Ecuadoran"],
    "Egypt": ["Egyptian"],
    "El Salvador": ["Salvadoran", "Salvadorian"],
    "Equatorial Guinea": ["Equatoguinean"],
    "Eritrea": ["Eritrean"],
    "Estonia": ["Estonian"],
    "Eswatini": ["Swazi"],
    "Ethiopia": ["Ethiopian"],
    "Fiji": ["Fijian"],
    "Finland": ["Finnish", "Finn"],
    "France": ["French"],
    "Gabon": ["Gabonese"],
    "Gambia": ["Gambian"],
    "Georgia": ["Georgian"],
    "Germany": ["German"],
    "Ghana": ["Ghanaian"],
    "Greece": ["Greek", "Hellenic"],
    "Grenada": ["Grenadian"],
    "Guatemala": ["Guatemalan"],
    "Guinea": ["Guinean"],
    "Guinea-Bissau": ["Bissau-Guinean"],
    "Guyana": ["Guyanese"],
    "Haiti": ["Haitian"],
    "Honduras": ["Honduran"],
    "Hungary": ["Hungarian", "Magyar"],
    "Iceland": ["Icelandic", "Icelander"],
    "India": ["Indian"],
    "Indonesia": ["Indonesian"],
    "Iran": ["Iranian", "Persian"],
    "Iraq": ["Iraqi"],
    "Ireland": ["Irish"],
    "Israel": ["Israeli", "Israelite"],
    "Italy": ["Italian"],
    "Ivory Coast": ["Ivorian"],
    "Jamaica": ["Jamaican"],
    "Japan": ["Japanese"],
    "Jordan": ["Jordanian"],
    "Kazakhstan": ["Kazakhstani", "Kazakh"],
    "Kenya": ["Kenyan"],
    "Kiribati": ["I-Kiribati"],
    "Kosovo": ["Kosovar"],
    "Kuwait": ["Kuwaiti"],
    "Kyrgyzstan": ["Kyrgyz", "Kirghiz"],
    "Laos": ["Laotian", "Lao"],
    "Latvia": ["Latvian"],
    "Lebanon": ["Lebanese"],
    "Lesotho": ["Basotho", "Mosotho"],
    "Liberia": ["Liberian"],
    "Libya": ["Libyan"],
    "Liechtenstein": ["Liechtenstein"],
    "Lithuania": ["Lithuanian"],
    "Luxembourg": ["Luxembourgish", "Luxembourger"],
    "Madagascar": ["Malagasy", "Madagascan"],
    "Malawi": ["Malawian"],
    "Malaysia": ["Malaysian"],
    "Maldives": ["Maldivian"],
    "Mali": ["Malian"],
    "Malta": ["Maltese"],
    "Marshall Islands": ["Marshallese"],
    "Mauritania": ["Mauritanian"],
    "Mauritius": ["Mauritian"],
    "Mexico": ["Mexican"],
    "Micronesia": ["Micronesian"],
    "Moldova": ["Moldovan"],
    "Monaco": ["Monegasque"],
    "Mongolia": ["Mongolian"],
    "Montenegro": ["Montenegrin"],
    "Morocco": ["Moroccan"],
    "Mozambique": ["Mozambican"],
    "Myanmar": ["Burmese", "Myanmarese"],
    "Namibia": ["Namibian"],
    "Nauru": ["Nauruan"],
    "Nepal": ["Nepali", "Nepalese"],
    "Netherlands": ["Dutch"],
    "New Zealand": ["New Zealander", "Kiwi"],
    "Nicaragua": ["Nicaraguan"],
    "Niger": ["Nigerien"],
    "Nigeria": ["Nigerian"],
    "North Korea": ["North Korean"],
    "North Macedonia": ["Macedonian", "North Macedonian"],
    "Norway": ["Norwegian"],
    "Oman": ["Omani"],
    "Pakistan": ["Pakistani"],
    "Palau": ["Palauan"],
    "Palestine": ["Palestinian"],
    "Panama": ["Panamanian"],
    "Papua New Guinea": ["Papua New Guinean"],
    "Paraguay": ["Paraguayan"],
    "Peru": ["Peruvian"],
    "Philippines": ["Filipino", "Filipina", "Philippine"],
    "Poland": ["Polish"],
    "Portugal": ["Portuguese"],
    "Qatar": ["Qatari"],
    "Romania": ["Romanian"],
    "Russia": ["Russian"],
    "Rwanda": ["Rwandan"],
    "Saint Kitts and Nevis": ["Kittitian", "Nevisian"],
    "Saint Lucia": ["Saint Lucian"],
    "Saint Vincent and the Grenadines": ["Vincentian"],
    "Samoa": ["Samoan"],
    "San Marino": ["Sammarinese"],
    "Sao Tome and Principe": ["Sao Tomean"],
    "Saudi Arabia": ["Saudi", "Saudi Arabian"],
    "Senegal": ["Senegalese"],
    "Serbia": ["Serbian", "Serb"],
    "Seychelles": ["Seychellois"],
    "Sierra Leone": ["Sierra Leonean"],
    "Singapore": ["Singaporean"],
    "Slovakia": ["Slovak", "Slovakian"],
    "Slovenia": ["Slovenian", "Slovene"],
    "Solomon Islands": ["Solomon Islander"],
    "Somalia": ["Somali"],
    "South Africa": ["South African"],
    "South Korea": ["South Korean"],
    "South Sudan": ["South Sudanese"],
    "Spain": ["Spanish"],
    "Sri Lanka": ["Sri Lankan", "Sinhalese"],
    "Sudan": ["Sudanese"],
    "Suriname": ["Surinamese"],
    "Sweden": ["Swedish"],
    "Switzerland": ["Swiss"],
    "Syria": ["Syrian"],
    "Taiwan": ["Taiwanese"],
    "Tajikistan": ["Tajik", "Tajikistani"],
    "Tanzania": ["Tanzanian"],
    "Thailand": ["Thai"],
    "Timor-Leste": ["Timorese", "East Timorese"],
    "Togo": ["Togolese"],
    "Tonga": ["Tongan"],
    "Trinidad and Tobago": ["Trinidadian", "Tobagonian"],
    "Tunisia": ["Tunisian"],
    "Turkey": ["Turkish"],
    "Turkmenistan": ["Turkmen", "Turkmenistani"],
    "Tuvalu": ["Tuvaluan"],
    "Uganda": ["Ugandan"],
    "Ukraine": ["Ukrainian"],
    "United Arab Emirates": ["Emirati"],
    "United Kingdom": ["British"],
    "United States": ["American"],
    "Uruguay": ["Uruguayan"],
    "Uzbekistan": ["Uzbek", "Uzbekistani"],
    "Vanuatu": ["Ni-Vanuatu"],
    "Vatican City": ["Vatican"],
    "Venezuela": ["Venezuelan"],
    "Vietnam": ["Vietnamese"],
    "Yemen": ["Yemeni"],
    "Zambia": ["Zambian"],
    "Zimbabwe": ["Zimbabwean"],
}


async def main(dry_run: bool) -> None:
    async with async_session() as db:
        countries = (await db.execute(select(Country).order_by(Country.name))).scalars().all()

        updated = 0
        added_total = 0
        for country in countries:
            candidates = COUNTRY_ALIASES.get(country.name, [])
            if not candidates:
                continue

            existing = list(country.aliases or [])
            seen = {a.lower() for a in existing}
            added = []
            for alias in candidates:
                if alias.lower() in seen or alias.lower() == country.name.lower():
                    continue
                existing.append(alias)
                seen.add(alias.lower())
                added.append(alias)

            if added:
                # Reassign rather than mutate — ARRAY columns need a new list to dirty the row.
                country.aliases = existing
                print(f"  {country.name}: +{', '.join(added)}")
                updated += 1
                added_total += len(added)

        verb = "would gain" if dry_run else "gained"
        print(f"\n{updated} countries {verb} {added_total} aliases.")
        if dry_run:
            await db.rollback()
        else:
            await db.commit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Report changes without writing.")
    asyncio.run(main(parser.parse_args().dry_run))
