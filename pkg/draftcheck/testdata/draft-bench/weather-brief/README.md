# three-line-weather-brief

Looks up a city you name on Open-Meteo and answers in exactly three lines: right now, today, tomorrow. No API key.

Type a city and get a three-line weather brief back. The BriefAgent resolves the name to coordinates with Open-Meteo's free geocoding API, then reads current conditions and a two-day forecast from its forecast API. Line 1 is right now, line 2 is today with sunrise and sunset, line 3 is tomorrow. Neither call needs an API key.

Drafted by the Drafter (`agentry draft`). Review the manifest, the instructions and this file before you publish;
this README renders on the BriefAgent's page.
