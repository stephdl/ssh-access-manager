# ui/CLAUDE.md — Frontend Vue.js 3

## Vues (ui/src/views/)

| Vue | Rôle |
|-----|------|
| Login.vue | Connexion + checkbox "Keep me logged on this device" (#239) |
| Dashboard.vue | Tableau serveurs + recherche + compteurs + modal ajout serveur (#71) + clé collecteur (#74) |
| ServerDetail.vue | Détail serveur + clés + actions + bandeau rouge si désactivé (#91) |
| Anomalies.vue | Anomalies actives + filtres texte/type/serveur/conformité + colonne unix_user (#195) |
| AccessRequests.vue | DeployKeyForm + UserLockForm |
| Audit.vue | Historique filtrable |
| Admins.vue | Gestion admins + modals enable/delete/password + garde-fou self (#116) + toggle alerts (#223) |
| Settings.vue | scan_interval_hours, expire_warn_days*, login_max_attempts, login_ban_seconds (#236) + test SMTP |

## Composants (ui/src/components/)

| Composant | Rôle |
|-----------|------|
| ServerTable.vue | Tableau serveurs + ligne grisée + badge rouge si désactivé (#91) |
| KeyTable.vue | Tableau clés + filtres texte + dropdown statut (#189) + bouton Illimité (#93) + tooltip non-conformité |
| KeyActions.vue | Boutons valider/révoquer/expiry |
| ExpiryPicker.vue | Modes exclusifs heures / date précise |
| DeployKeyForm.vue | Formulaire déploiement clé SSH |
| UserLockForm.vue | Verrouillage/déverrouillage compte Unix (#181) |
| DeployedUsersTable.vue | Utilisateurs Unix déployés + filtres + RBAC operator/viewer |

## Composables

- `useAuth.js` — authentification session
- `useFormatDate.js` — `formatDate()` et `formatDateOnly()` avec locale navigateur (#228, UTC→local)

## Internationalisation — règle absolue

**Toute clé de traduction doit être présente dans les 5 fichiers JSON :**
`locales/en.json`, `fr.json`, `es.json`, `it.json`, `de.json`

Détection automatique de la langue du navigateur via vue-i18n v9 (i18n.js).

## Règles UI transversales

- **Boutons désactivés** (#107) : CSS global `button:disabled` → opacity 45%, cursor not-allowed, grayscale
- **Serveurs désactivés** (#91) : ligne grisée dans ServerTable + bandeau rouge en haut dans ServerDetail
- **Backend** : uniquement les routes `/api/` définies dans app/CLAUDE.md — ne jamais appeler autre chose
- Les timestamps sont stockés UTC en base, affichés dans le fuseau du navigateur via useFormatDate.js

## Tests Vitest (ui/tests/)

| Fichier | Tests | Ce qui est vérifié |
|---------|-------|--------------------|
| KeyActions.spec.js | 14 | modal confirmation révocation |
| ExpiryPicker.spec.js | 9 | modes exclusifs heures/date |
| ServerTable.spec.js | 15 | filtres hostname/IP/env, badges statut |
| KeyTable.spec.js | 30 | boutons par statut, owner, expires_at, filtres |
| Admins.spec.js | 31 | modals enable/delete, RBAC, toggle alerts |
| Settings.spec.js | 14 | validation champs, SMTP test |
| DeployKeyForm.spec.js | 16 | formulaire déploiement clé SSH |
| UserLockForm.spec.js | 10 | lock/unlock compte Unix |
| DeployedUsersTable.spec.js | 12 | filtres, RBAC operator/viewer |
| Anomalies.spec.js | 20 | filtres texte + dropdowns, unix_user, badges |
| Login.spec.js | 8 | checkbox remember-me, payload remember_me |

vitest doit passer avant tout commit.
