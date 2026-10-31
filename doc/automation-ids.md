# Automation IDs for GUI test bots

Stable identifiers for the GUI elements of XCA, for bot-driven GUI tests through the
accessibility layer (BTD-61; harness BTD-62, regression list BTD-40). The IDs are Qt
`objectName`s. They never change with the language, the visible text or the layout.

## How a bot sees them

| Platform | Interface | Where the ID shows up |
|---|---|---|
| Linux | AT-SPI (D-Bus, Qt plugin `libQt6DBus`) | accessible id = path of objectNames, e.g. `XcaApplication.MainWindow.centralWidget.tabView.qt_tabwidget_stackedwidget.KeyTab.keyButtons.BNnewKey` (measured with Qt 6.8.2, BTD-62) |
| Windows | UI Automation | `AutomationId` = objectName (inferred, verified in BTD-13) |

A widget or action without an objectName shows up under its class name (`QAction`,
`QPushButton`), which is ambiguous. The accessible *name* is the visible text or the
`accessibleName`; it is translated and therefore not an ID, but it helps where a widget has
no visible label.

## Scheme

IDs use `[A-Za-z0-9_]` only. Parts are separated by `_`; inside a part, camelCase.

| Element | Pattern | Example |
|---|---|---|
| Widgets from the Designer files (`ui/*.ui`) | the Designer name, unchanged | `BNnewKey`, `keyView`, `passA` |
| Menu bar | `menu_bar` | |
| Menu of the menu bar | `menu_<menu>` | `menu_file`, `menu_language` |
| Menu bar action | `act_<menu>_<action>` | `act_file_openDatabase` |
| Language entry | `act_lang_<locale>`, `act_lang_system` | `act_lang_de` |
| Recent database entry | `act_history_<n>` (n as in the visible text, from 0) | `act_history_0` |
| Context menu of a tree view | `ctx_<view>` | `ctx_cert` |
| Context menu entry or submenu | `ctx_<view>_<action>`, submenu entries `ctx_<view>_<submenu>_<action>` | `ctx_cert_ca_generateCrl` |
| Column menu (header or context menu) | `ctx_<view>_columns[_<submenu>]` | `ctx_key_columns`, `ctx_cert_columns_v3ext` |
| Column on/off entry | `col_<OpenSSL short name>` for subject and extension columns, `col_<name>` for the others | `col_CN`, `col_basicConstraints`, `col_notAfter` |
| Standard dialog button (`QDialogButtonBox`, message box) | `btn_<StandardButton>` with a lower-case first letter | `btn_ok`, `btn_cancel`, `btn_yesToAll` |
| Message box | `dlg_message` (information, question), `dlg_warning` (warning/error box with extra buttons) | |
| Widget created in code inside a window or dialog | `dlg_<dialog>_<field>` | `dlg_main_search`, `dlg_newX509_dn_CN` |
| Distinguished name display (`DistName`) | `dn_<short name>`, label `dnLabel_<short name>`, repeated entries `_2`, `_3`; `dn_rfc2253`, `dn_hash` | `dn_OU_2` |
| Key fingerprints (key details) | `fp_<type>`, label `fpLabel_<type>` | `fp_DER_SHA256` |
| Request attributes (CSR details) | `attr_<short name>`, label `attrLabel_<short name>` | `attr_challengePassword` |

A menu and its `menuAction()` carry the same ID: the accessibility tree shows a submenu entry
as that action, so the path reads `menu_bar.menu_file.menu_file.act_file_exit`.

`<view>` is the Designer name of the tree view without `View`: `key`, `req`, `cert`, `temp`,
`crl`. Context menu IDs are unique inside one context menu; the same action in two views has
two IDs (`ctx_key_delete`, `ctx_cert_delete`).

## Fixed IDs

**Menu bar.**

| Menu | Actions |
|---|---|
| `menu_file` | `act_file_newDatabase`, `act_file_openDatabase`, `act_file_openRemoteDatabase`, `menu_history` (`act_history_<n>`), `act_file_setDefaultDatabase`, `act_file_closeDatabase`, `act_file_options`, `menu_language` (`act_lang_*`), `act_file_exit` |
| `menu_import` | `act_import_keys`, `act_import_requests`, `act_import_certificates`, `act_import_pkcs12`, `act_import_pkcs7`, `act_import_template`, `act_import_crl`, `act_import_pemFile`, `act_import_pastePem` |
| `menu_token` | `act_token_manage`, `act_token_init`, `act_token_changePin`, `act_token_changeSoPin`, `act_token_initPin` |
| `menu_extra` | `act_extra_dumpDatabase`, `act_extra_exportIndex`, `act_extra_exportIndexHierarchy`, `act_extra_changeDbPassword`, `act_extra_verifyAudit`, `act_extra_changeTableFont`, `act_extra_resetTableFont`, `act_extra_generateDhParam`, `act_extra_oidResolver` |
| `menu_help` | `act_help_content`, `act_help_about` |

In the App Store build the language menu and `act_file_options` sit in `menu_extra`; the IDs
stay the same.

**Context menus** (`ctx_<view>_…`; which entries appear depends on the selection, as before).

| Views | Entries |
|---|---|
| all | `new`, `import`, `pastePem`, `rename`, `properties`, `delete`, `export` (`export_clipboard`, `export_file`), `clipboardFormat` (`clipboardFormat_<export id>`, the fixed ids of `lib/pki_export.cpp`), `columns` |
| `key` | `changePassword`, `resetPassword`, `changePin`, `initPin`, `changeSoPin`, `export_token` |
| `req`, `cert` | `transform` (`transform_template`, `transform_publicKey`) |
| `req` | `sign`, `markSigned`, `unmarkSigned`, `transform_similarRequest` |
| `cert` | `hideUnusable`, `importPkcs12`, `importPkcs7`, `transform_request`, `transform_similarCertificate`, `export_token`, `export_otherToken`, `deleteFromToken`, `ca` (`ca_properties`, `ca_generateCrl`, `ca_manageRevocations`), `importTaKey`, `renewal`, `revoke`, `unrevoke` |
| `temp` | `duplicate`, `createCertificate`, `createRequest` |

Column menu entries: `columns_reset`, `columns_hide`, `columns_details`, the submenus
`columns_subject`, `columns_v3ext`, `columns_netscape` (inside `columns_v3ext`),
`columns_key`, and the `col_*` toggles.

**Widgets created in code.**

| ID | Widget |
|---|---|
| `dlg_main_search` | search field in the status bar (accessible name "Search") |
| `dlg_main_dbStatus` | "Database: …" label in the status bar |
| `dlg_newX509_dn_<sn>`, `dlg_newX509_dnLabel_<sn>` | explicit subject fields of the certificate/request dialog, tab Subject (accessible name = label text) |
| `dlg_newX509_attr_<sn>`, `dlg_newX509_attrLabel_<sn>` | request attributes (`unstructuredName`, `challengePassword`), tab Source |
| `dlg_pastePem_text` | text field of Import → Paste PEM |
| `dlg_about_text` | text of the About dialog |
| `dlg_warningV3_text` | text of the extension warning dialog |
| `dlg_auditVerify`, `dlg_auditVerify_<field>` | Extra → Verify audit log (BTD-103) and its values: `ok`, `entries`, `firstBrokenSeq`, `reason`, `checkpoints`, `lastCheckpointSeq`, `unanchoredEntries`, `auditKeys`, `adoptedEntries`, `unauditedRevocations` (accessible name = the value shown, the caption is `dlg_auditVerify_label_<field>`); `dlg_auditVerify_mismatches` (table), `dlg_auditVerify_pinKeys`, `dlg_auditVerify_minCheckpoint`; buttons `btn_verify`, `btn_adopt`, `btn_close` |

## Accessible names

Set where a widget has no visible text of its own, so that a screen reader and a bot get a
name: the five tree views of the main window (the tab title), the search field, the four
check boxes without text in the CRL dialog, the subject fields of the certificate dialog and
the read-only fields of `DistName`. Strings already translated in the same context are
reused, so translations do not change.

Most Designer widgets have a label next to them that is not linked as buddy; their AT-SPI
name is empty, their objectName ID is set. Linking the labels is a separate change.

## Rules for new code

- Every `QAction`, `QMenu` and interactive widget created in code gets an objectName from
  this scheme, e.g. `setAutomationId(menu->addAction(...), ctxId("myAction"))`
  (`widgets/AutomationId.h`, `XcaTreeView::ctxId()`).
- Dialog standard buttons need nothing: `AutomationId::install()` (called by
  `XcaApplication`) names them when a dialog is shown.
- Never change an existing ID; a bot script depends on it. Add the new ID to this file.
- The ctest `test_automation_ids` walks the menu bar, all tree view context menus, the
  column menus and some dialogs and fails on an empty, malformed or duplicate ID.
