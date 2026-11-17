---
name: dependencies-bijwerken
description: Werk de Go dependencies van aws-keyhub bij volgens de procedure in README.md. Draait `go get -u && go mod tidy` in een golang docker container, controleert op verouderde/gearchiveerde dependencies, bouwt de binaries lokaal met build-release.sh en test de basiscommando's en de browserCommand instelling. Sluit af met een checklist voor PR, release en aankondiging.
allowed-tools: Bash(docker *) Bash(git *) Bash(gh *) Bash(grep *) Bash(cat *) Bash(go *) Bash(./build-release.sh) Bash(./build/*) Read AskUserQuestion
---

Voer de volgende stappen uit om de Go dependencies van aws-keyhub bij te werken. Voer elke stap volledig uit voordat je verdergaat.

---

## Stap 0: Controleer de working tree

```
git status --short
```

Als er ongecommitte wijzigingen zijn, meld dit aan de gebruiker en vraag of je verder mag gaan of dat deze eerst weggezet moeten worden. Ga anders direct verder.

---

## Stap 1: Update de dependencies in een golang container

Volg de procedure uit `README.md` ("Update dependencies procedure"), maar niet-interactief zodat de output gelogd kan worden:

```
docker run --rm -v go-mod-cache:/go/pkg/mod -v "$(pwd)":/app -w /app golang:1.26 \
  bash -c "apt-get update -qq && apt-get install -y -qq zip && go get -u && go mod tidy"
```

Controleer daarna wat er gewijzigd is:

```
git diff go.mod go.sum
```

Als er niets gewijzigd is (alle dependencies waren al up-to-date), meld dit aan de gebruiker en vraag of de skill toch moet doorgaan (bijvoorbeeld om alsnog de archived-check en build/test te draaien) of hier moet stoppen.

---

## Stap 2: Controleer op verouderde of gearchiveerde dependencies

Haal de directe dependencies op (het eerste `require (...)` blok in `go.mod`, dus **zonder** de `// indirect` regels). Bepaal per dependency de onderliggende GitHub repo (owner/repo, zonder submodule-pad of major-versiesuffix zoals `/v2`). Bijvoorbeeld `github.com/aws/aws-sdk-go-v2/service/sts` hoort bij repo `aws/aws-sdk-go-v2`.

Check voor elke unieke GitHub repo of deze gearchiveerd is en wanneer er voor het laatst naar gepusht is:

```
gh api repos/<owner>/<repo> --jq '{archived: .archived, pushed_at: .pushed_at, html_url: .html_url}'
```

Let hierbij specifiek op `github.com/AlecAivazis/survey` (`AlecAivazis/survey`) — deze staat bekend als een dependency die mogelijk niet meer onderhouden wordt.

- Als een dependency **gearchiveerd** is, of al **meer dan ~1 jaar** niet meer gepusht is: meld dit aan de gebruiker met de repo-naam en laatste push-datum, en vraag (via `AskUserQuestion`):
  > Dependency `<module>` lijkt niet meer onderhouden te worden (gearchiveerd: <ja/nee>, laatste update: <datum>). Wil je dat ik nu al naar een alternatief zoek en vervang, of moet ik dit overslaan zodat er een apart ticket voor aangemaakt kan worden?
- Als niets afwijkt: meld kort dat alle directe dependencies actief onderhouden worden en ga direct verder naar stap 3.

---

## Stap 3: Bouw de binaries lokaal

`go` staat mogelijk niet in de PATH van deze sessie. Los dat zo nodig op:

```
PATH="/usr/local/go/bin:$PATH" ./build-release.sh
```

Dit bouwt alle platform-binaries (linux/windows/darwin, amd64/arm64) en maakt de release-zips aan in `release/`. Als het script faalt, toon de foutmelding en stop — los het probleem op voordat je verdergaat.

---

## Stap 4: Test de basiscommando's

Voer de automatiseerbare smoke tests uit op de linux-build:

```
./build/linux-amd64/aws-keyhub version
./build/linux-amd64/aws-keyhub help
./build/linux-amd64/aws-keyhub configure --help
./build/linux-amd64/aws-keyhub login --help
```

Controleer dat elk commando zonder crash of onverwachte error teruggeeft, en dat `help` in ieder geval `login` als subcommando toont.

`configure`, `login` en `login --role-arn` vereisen een interactieve prompt (survey) respectievelijk een echte KeyHub-organisatie en browser-flow, en kunnen niet door jou volledig getest worden. Meld daarom aan de gebruiker:

> De automatische checks (`version`, `help`, `--help` van `configure`/`login`) zijn geslaagd.
> Test zelf nog handmatig, met een echte KeyHub-configuratie:
> - `aws-keyhub configure`
> - `aws-keyhub login`
> - `aws-keyhub login --role-arn <een geldige role-arn>`
> - `aws-keyhub login` met een `browserCommand` in `~/.aws-keyhub/config-v2.json` (bijv. `["firefox", "-P", "<profiel>", "{url}"]`, zie README) — opent de login-link in de gekozen browser/profiel?

---

## Stap 4b: Test de `browserCommand` instelling

Draai eerst de Go unit tests (o.a. `buildBrowserCommand` en het detachen van het browserproces):

```
PATH="/usr/local/go/bin:$PATH" go test ./...
```

Draai daarna de end-to-end test van de `browserCommand` instelling op de linux-build:

```
.claude/skills/dependencies-bijwerken/test-browser-command.sh ./build/linux-amd64/aws-keyhub
```

Dit script draait `aws-keyhub login` tegen een nep-KeyHub (lokale python HTTP server) met een tijdelijke `HOME`, dus de echte configuratie wordt niet aangeraakt. Het controleert:

- `{url}` als los argument wordt vervangen, en argumenten met spaties blijven één argument
- zonder `{url}` wordt de link als laatste argument toegevoegd
- `{url}` midden in een argument (`--app={url}`) wordt vervangen
- niet-bestaand commando → waarschuwing + fallback naar de default browser
- commando dat met een fout eindigt → waarschuwing + fallback naar de default browser
- geen / lege / blanco `browserCommand` → default browser

Elk scenario toont `PASS` of `FAIL` (met verwachte en werkelijke output); het script eindigt met exit code 0 als alles slaagt. Als er iets faalt: toon de output aan de gebruiker en stop.

---

## Stap 5: Afronden en vervolgstappen

Toon een korte samenvatting van de bijgewerkte dependencies (uit de `git diff go.mod` van stap 1: pakket, oude versie → nieuwe versie), en eventuele bevindingen uit stap 2.

Geef daarna letterlijk de volgende vervolgstappen aan de gebruiker:

> **Dependencies zijn bijgewerkt en lokaal gebouwd/getest.**
>
> Vervolgstappen (zelf te doen):
> 1. Maak een PR met de wijzigingen in `go.mod` / `go.sum`.
> 2. Maak een nieuwe release (nieuwe tag) zodra de PR gemerged is.
> 3. Test de nieuwe release op Windows, macOS en Linux.
> 4. Kondig de release aan bij **#public-cloud**.
