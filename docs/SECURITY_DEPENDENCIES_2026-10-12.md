# Correctif Logback du 12 octobre 2026

Correction de CVE-2026-104721 avec Logback 1.6.5, conformément à la
[publication officielle](https://github.com/qos-ch/logback/releases/tag/v_1.6.5).
Le correctif antérieur de la version 1.6.3 était insuffisant.

`logbackVersion` passe de 1.6.3 à 1.6.5. La règle de résolution aligne seulement
`logback-classic` et `logback-core`, sans modifier les autres modules du groupe.
Le plugin et la version effectivement utilisée de ktlint ne sont pas changés.

## Validation locale

- `dependencyInsight` confirme classic et core 1.6.5 dans le classpath `ktlint`.
  La demande transitive de classic 1.3.14 est remplacée par 1.6.5.
- `./gradlew verify` réussit avec JDK 21 et le SDK Android local.
- Tests unitaires, 92 réussites pour vault, 20 pour app et 12 pour webauthn.
- Android Lint réussit pour app, webauthn et rptest.
- Le worker ktlint s'exécute sans erreur de chargement Logback.
- La violation de style préexistante dans `PublicKeyCredential.kt:209`, règle
  `standard:function-expression-body`, a été reproduite avec Logback 1.6.3 et
  1.6.5, puis corrigée séparément à la demande de l'utilisateur.
  `getAllAccounts` utilise un corps d'expression sans changer le dispatcher ni
  la conversion des erreurs de stockage.
- `./gradlew :webauthn:ktlintCheck verify` réussit après cette correction.
  Les tests du module webauthn sont réexécutés, les autres suites restent à jour.
- Aucun commit, push ou déploiement.

Depuis la racine avec un JDK 21 configuré :

```sh
./gradlew :webauthn:dependencyInsight --dependency ch.qos.logback --configuration ktlint
./gradlew verify
./gradlew :webauthn:ktlintCheck
```

Un nouveau scan Snyk, la CI distante et les essais sur appareil ne sont pas
réalisés dans cette validation locale.
