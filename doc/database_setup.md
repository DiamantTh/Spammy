# Datenbank- und Benutzerbeispiele

Spammy überlässt dir die Wahl des relationalen Backends. Achte in jedem Fall
auf UTF‑8/utf8mb4/NVARCHAR-Encoding, damit internationale Inhalte korrekt
verarbeitet werden. Die folgenden Snippets dienen als Startpunkt – passe sie an
deine Umgebung an.

## PostgreSQL

```sql
CREATE ROLE spammy LOGIN PASSWORD 'geheim';
CREATE DATABASE spammy
  WITH OWNER spammy
       ENCODING 'UTF8'
       TEMPLATE template0
       LC_COLLATE 'en_US.UTF-8'
       LC_CTYPE 'en_US.UTF-8';
GRANT ALL PRIVILEGES ON DATABASE spammy TO spammy;
```

Optionale Partitionierung: PostgreSQL ≥10 erlaubt `PARTITION BY RANGE`/
`LIST`/`HASH`. Lege die Tabellen gemäß deinen Reporting-Anforderungen an und
nutze Migrationen/SQL-Skripte, um neue Partitionen hinzuzufügen.

## MariaDB / MySQL

```sql
CREATE DATABASE spammy
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
CREATE USER 'spammy'@'%' IDENTIFIED BY 'geheim';
GRANT ALL PRIVILEGES ON spammy.* TO 'spammy'@'%';
FLUSH PRIVILEGES;
```

Partitionierung (`PARTITION BY RANGE (...)`) steht sowohl in MySQL als auch in
MariaDB zur Verfügung, erfordert aber ggf. zusätzliche Indizes. Prüfe, ob dein
Schema/ORM dies unterstützt, bevor du produktiv gehst.

## Microsoft SQL Server

```sql
CREATE LOGIN spammy WITH PASSWORD = 'GeHeIm123!';
CREATE DATABASE Spammy COLLATE Latin1_General_100_CI_AS_SC_UTF8;
GO
USE Spammy;
CREATE USER spammy FOR LOGIN spammy;
EXEC sp_addrolemember 'db_owner', 'spammy';
```

Für Partitionierung kannst du Partition Functions/Schemes anlegen und Tabellen
entsprechend erstellen. Alternativ eignen sich separate Tabellen pro Zeitraum
oder materialisierte Views.

## Hinweise

- Passe Passwörter, Collations und Hostnamen an dein Deployment an.
- Wenn du Migrationstools (z.B. Django ORM, SQLAlchemy/Alembic) nutzt, halte
  deren Skripte unter Versionskontrolle und kombiniere sie mit den obigen
  Basisschritten.
- Der `storage`-Abschnitt in `config/spammy.toml` nimmt host/user/password-
  Angaben oder einen ODBC-DSN auf. Stelle sicher, dass die Einstellungen zu
  deiner Datenbank passen.
