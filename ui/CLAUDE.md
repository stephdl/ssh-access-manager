# ui/CLAUDE.md — Frontend Vue.js 3

## Vues (ui/src/views/)

| Vue | Rôle |
|-----|------|
| Login.vue | Connexion + checkbox "Keep me logged on this device" (#239) |
| Dashboard.vue | Tableau serveurs + recherche + compteurs + modal ajout serveur (#71) + clé collecteur (#74). Provisionnement atomique via SSH (#299, #301) : SSH user/password obligatoires, serveur créé uniquement si SSH réussit. Validation hostname RFC 1123 (#303). Layout 2 colonnes. |
| ServerDetail.vue | Détail serveur + clés + actions + bandeau rouge si désactivé (#91). Bouton **Edit** (sysadmin) : ouvre `EditServerModal` pour modifier IP, env, OS, port SSH (#339) ; `max_sessions` configurable via `EditServerModal` (seuil alertes sessions, #360). Bandeau orange si `last_scan_ok === false` (#324). Bouton **Re-provisionner** (violet, sysadmin + serveur actif) : modal SSH credentials, spinner, traduction error_code (#302). `bulkRevokeHasRoot` vérifie les clés composées (`\|root`) — évite faux positif quand un non-root partage le même fingerprint que root. **Bulk revoke fait du targeted per-row** : loop sur les composites, POST `/api/keys/revoke/<fp>` avec `{hostname, unix_user, reason}` au lieu d'un global `/api/keys/bulk-revoke` (qui serait refusé dès que root partage le fingerprint, #429). |
| Anomalies.vue | Anomalies actives + filtres texte/type/serveur/conformité + colonne unix_user (#195) |
| AccessRequests.vue | DeployKeyForm + UserLockForm |
| Audit.vue | Historique filtrable |
| Admins.vue | Gestion admins + modals enable/delete/password + garde-fou self (#116) + toggle alerts (#223) |
| Settings.vue | scan_interval_hours, expire_warn_days*, login_max_attempts, login_ban_seconds (#236), audit_retention_days (#346) + test SMTP |

## Composants (ui/src/components/)

| Composant | Rôle |
|-----------|------|
| ServerTable.vue | Tableau serveurs + ligne grisée + badge rouge si désactivé (#91) |
| KeyTable.vue | Tableau clés + filtres texte + dropdown statut (#189) + bouton Illimité (#93) + tooltip non-conformité + sélection en masse (bulk validate/revoke, #345). **Protection** : `PROTECTED_USERS = ['root', 'audit-collector']` via `isProtectedUser()` — Revoke et Expiry désactivés, `isSelectable` exclut, badge "protected", classe `.row-root` (background tinté **sans `opacity`** : l'opacité cascadait sur les boutons enabled et créait l'illusion qu'ils étaient disabled, #429). Tooltips dédiés : `root_revoke_tooltip` / `collector_revoke_tooltip` (pointe vers Rotate) ; `root_expiry_tooltip` / `collector_expiry_tooltip`. Sélection composite `fingerprint\|unix_user` (fix multi-user même fingerprint #345) ; `bulk-revoke` émet clés composées brutes |
| KeyActions.vue | Boutons valider/révoquer/expiry |
| ExpiryPicker.vue | Modes exclusifs heures / date précise |
| DeployKeyForm.vue | Formulaire déploiement clé SSH ; refuse `unix_user = 'root'` avec message d'erreur dédié |
| UserLockForm.vue | Verrouillage/déverrouillage compte Unix (#181) |
| DeployedUsersTable.vue | Utilisateurs Unix déployés + filtres + RBAC operator/viewer ; lignes root visuellement grisées (`.row-root`), badge "protected", tooltips sur boutons désactivés via `<span class="btn-tooltip-wrapper">` (fix navigateur : buttons disabled ne reçoivent pas les événements souris) |
| AdminsTable.vue | Tableau administrateurs + filtre texte + pagination + garde-fou self (#250) |
| AuditTable.vue | Tableau audit + filtres serveur/action/date + pagination (#250) |
| AnomaliesTable.vue | Tableau anomalies + filtres texte/type/serveur/conformité + pagination (#250). Même protection `PROTECTED_USERS = ['root', 'audit-collector']` que KeyTable : pas de checkbox sur ces lignes, badge "protected", classe `.row-root`, Revoke disabled avec tooltip dédié. Sélection composite à 3 niveaux **`fingerprint\|server_hostname\|unix_user`** (matchant la PK composite de `key_authorizations` #185) — sans le 3ᵉ niveau, deux lignes même fp+serveur mais users différents partageaient la même clé de sélection (#429). `bulk-revoke` émet `{fingerprint, hostname, unix_user}[]` ; le single-Revoke émet `{fingerprint, hostname, unix_user}` aussi pour que la modal fasse un revoke ciblé (sinon le global revoke est refusé par le backend dès que root partage le fingerprint) |
| PaginationBar.vue | Composant pagination réutilisable avec contrôles taille de page |
| SessionsCard.vue | Sessions SSH actives + modal Full History (filtres user/ip/date, pagination, export CSV) — sysadmin/operator uniquement (#253) |
| Spinner.vue | Spinner animé universel — utilisé dans tous les boutons en état de chargement (#337) |
| EditServerModal.vue | Modal édition serveur (IP, env, OS, port SSH) — partagé par Dashboard et ServerDetail. Props : `modelValue` (v-model), `server`, `allServers` (optionnel, pour validation doublon IP). Émet `saved` après PUT /api/servers/{hostname} (#337, #339) |

## Composables

- `useAuth.js` — authentification session + détection 401 → redirection automatique vers `/login` via `apiFetch` (session expirée — #312)
- `useFormatDate.js` — `formatDate()` et `formatDateOnly()` avec locale navigateur (#228, UTC→local)
- `usePagination.js` — pagination côté client réutilisable (10 lignes par défaut, reset auto au changement de filtre)
- `useSort.js` — tri de colonnes réutilisable (`sortKey`, `toggleSort`, `sorted`, `sortIndicator`) — utilisé dans KeyTable, ServerTable, AuditTable, DeployedUsersTable, AdminsTable, AnomaliesTable
- `useTheme.js` — thème sombre/clair (`isDark`, `toggleTheme`, `initializeTheme`) — persistance via localStorage, défaut dark (#363)

## Internationalisation — règle absolue

**Toute clé de traduction doit être présente dans les 5 fichiers JSON :**
`locales/en.json`, `fr.json`, `es.json`, `it.json`, `de.json`

Détection automatique de la langue du navigateur via vue-i18n v9 (i18n.js).

## Règles UI transversales

- **Boutons désactivés** (#107) : CSS global `button:disabled` → opacity 45%, cursor not-allowed, grayscale
- **Serveurs désactivés** (#91) : ligne grisée dans ServerTable + bandeau rouge en haut dans ServerDetail
- **Backend** : uniquement les routes `/api/` définies dans app/CLAUDE.md — ne jamais appeler autre chose
- Les timestamps sont stockés UTC en base, affichés dans le fuseau du navigateur via useFormatDate.js
- **Validation IP dans Dashboard.vue** (#271) : `isValidIp()` (format IPv4/IPv6) + `isIpDuplicate()` (unicité globale contre `servers.value` — actifs ET désactivés). Bouton désactivé + message `.field-error` inline si invalide ou doublon.

## Tests Vitest (ui/tests/)

| Fichier | Tests | Ce qui est vérifié |
|---------|-------|--------------------|
| KeyActions.spec.js | 14 | modal confirmation révocation |
| ExpiryPicker.spec.js | 9 | modes exclusifs heures/date |
| ServerTable.spec.js | 25 | filtres hostname/IP/env, badges statut |
| KeyTable.spec.js | 49 | boutons par statut, owner, expires_at, filtres, protection root (grisage, badge, sélection exclue) |
| Admins.spec.js | 31 | modals enable/delete, RBAC, toggle alerts |
| Settings.spec.js | 18 | validation champs, SMTP test |
| DeployKeyForm.spec.js | 16 | formulaire déploiement clé SSH |
| UserLockForm.spec.js | 10 | lock/unlock compte Unix |
| DeployedUsersTable.spec.js | 21 | filtres, RBAC operator/viewer, lien serveur, colonne IP, protection root (grisage, badge, tooltips) |
| ServerDetail.spec.js | 7 | root warnings + expiry scoping |
| Anomalies.spec.js | 20 | filtres texte + dropdowns, unix_user, badges |
| Login.spec.js | 8 | checkbox remember-me, payload remember_me |
| AdminsTable.spec.js | 13 | filtre texte, pagination, RBAC, garde-fou self, events (#250) |
| AuditTable.spec.js | 10 | filtres serveur/action/date, pagination, row classes (#250) |
| AnomaliesTable.spec.js | 22 | filtres texte/type/conformité, pagination, RBAC, events (#250) |
| SessionsCard.spec.js | 17 | sessions actives, modal historique, filtres, pagination, CSV export, RBAC (#253) |
| Dashboard.spec.js | 8 | champs SSH obligatoires, submit désactivé sans password/hostname invalide, POST avec ssh_user/password/port, port 22 par défaut, fermeture modal, validation RFC 1123 (#299, #303) |
| PaginationBar.spec.js | 10 | sélecteur taille, navigation pages, désactivation limites |
| App.spec.js | 8 | SMTP banner, sélecteur langue, persistance localStorage |
| useSort.spec.js | 21 | tri multi-colonnes, reset, indicateurs |

<!-- 20 fichiers de tests -->
vitest doit passer avant tout commit.
