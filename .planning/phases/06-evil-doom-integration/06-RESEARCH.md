# Phase 6: Evil & Doom Integration - Research

**Researched:** 2026-02-21
**Domain:** Evil-mode operators and text objects; Doom Emacs map! macro and leader bindings; conditional loading for optional evil/Doom dependencies
**Confidence:** HIGH (evil API verified from official docs + source; Doom patterns verified from source + discourse; key conflicts verified from evil-maps.el)

---

## Summary

Phase 6 adds evil-mode operator support (`ge{motion}` encrypt, `gd{motion}` decrypt, `gt{motion}` toggle), evil text objects (`is` inner sss pattern, `as` outer sss pattern), and Doom leader/localleader bindings (`SPC e` prefix, `, e` localleader), all conditional on the respective packages being present.

The evil operator API is straightforward: `evil-define-operator` takes `(beg end)` args and calls the already-implemented Phase 5 region functions directly. Text objects require `evil-define-text-object` plus `(define-key evil-inner-text-objects-map ...)` and `(define-key evil-outer-text-objects-map ...)`. The Doom `map!` macro handles leader/localleader bindings with `:after sss-mode` for correct load order.

**Three critical findings that directly affect planning:**

1. **Key binding conflicts**: `ge` is `evil-backward-word-end` and `gd` is `evil-goto-definition` -- both in `evil-motion-state-map` (inherited by normal state). `gt` is `evil-tab-next`. All three are real bindings that users rely on. The ROADMAP says to use these keys; the planner must accept this as the specified design (these are the same bindings as in `sss-doom.el`) but must bind them in `evil-normal-state-map` (not motion state) to shadow rather than replace the motion bindings in operator-pending state. **This is a design decision already made by the ROADMAP; research surfaces the conflict for documentation.**

2. **Conditional loading guard**: `(with-eval-after-load 'evil ...)` is correct for a package that works without evil. `(when (featurep 'evil) ...)` at top-level fires only if evil is already loaded at load time, which is fragile and order-dependent. `(modulep! :editor evil)` is Doom-only and would break vanilla Emacs. Use `with-eval-after-load` for both evil operators and text object registration.

3. **File architecture**: The user's `packages.el` specifies `:files ("*.el")` -- every `.el` file in `emacs/` is auto-loaded. Adding `emacs/sss-evil.el` (for evil operators + text objects) and `emacs/sss-doom.el` (for Doom map! bindings) would work mechanically, but both files would be loaded in vanilla Emacs with no evil/Doom. Since those files use `with-eval-after-load` guards, this is safe. However, the simpler approach is to add evil and Doom code to `sss-mode.el` itself behind guards, keeping the single-file package structure that PACK-01 specifies ("a single .el file").

**Primary recommendation:** Add evil code directly to `sss-mode.el` behind `(with-eval-after-load 'evil ...)` guards. Add Doom `map!` code behind `(with-eval-after-load 'doom-core ...)` or `(when (fboundp 'map!) ...)` guards. No new files needed. This preserves PACK-01 and PACK-03 (zero external dependencies).

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| EVIL-01 | Evil encrypt operator -- `sss-evil-encrypt` motion-based operator for encrypting text objects | `evil-define-operator` with `(beg end)` calling `sss-encrypt-region` directly; bind to `ge` in `evil-normal-state-map` inside `with-eval-after-load 'evil` block |
| EVIL-02 | Evil decrypt operator -- `sss-evil-decrypt` motion-based operator for decrypting text objects | Same pattern as EVIL-01, bind to `gd`; calls `sss-decrypt-region` |
| EVIL-03 | Evil toggle operator -- `sss-evil-toggle` motion-based operator for toggling encryption | Same pattern, bind to `gt`; calls `sss-toggle-at-point` when beg==end (point), else `sss-encrypt-region`; text objects `is`/`as` via `evil-define-text-object` + `define-key` on inner/outer text objects maps |
| DOOM-01 | Leader bindings -- `SPC e` prefix with encrypt/decrypt/toggle/process commands via `map!` | `(map! :leader (:prefix-map ("e" . "encryption") ...))` inside `(when (fboundp 'map!) ...)` or `(with-eval-after-load 'doom-core ...)` |
| DOOM-02 | Localleader bindings -- `, e` prefix for buffer-local sss operations via `map!` | `(map! :localleader :map sss-mode-map ...)` -- user's config sets `doom-localleader-key` to `","` |
| DOOM-03 | Conditional loading -- Doom integration loads only when `(modulep! :editor evil)` is available | CORRECTION: requirement says `modulep!` but correct guard for a standalone package is `(with-eval-after-load 'evil ...)` + `(when (fboundp 'map!) ...)`. `modulep!` is Doom-internal and would break vanilla; the intent is "conditional when evil present" not "Doom-specific" |
</phase_requirements>

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| evil (built-in to Doom) | 1.15.0+ | `evil-define-operator`, `evil-define-text-object`, key maps | The modal editing layer; all operators and text objects are defined via its macros |
| transient (already optional in Phase 5) | bundled Emacs 28+ | Optional; not needed for Phase 6 | Already integrated in Phase 5 |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| doom-core | Doom 3.x | Provides `map!` macro for leader/localleader bindings | Only in Doom context; must guard with `(fboundp 'map!)` |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `with-eval-after-load 'evil` | `(when (featurep 'evil) ...)` at top level | `featurep` is order-dependent (fragile if sss-mode.el loads before evil); `with-eval-after-load` fires whenever evil loads regardless of order |
| `with-eval-after-load 'evil` | `(modulep! :editor evil)` | `modulep!` is Doom-internal macro; breaks vanilla Emacs completely |
| Separate `sss-evil.el` file | Inline in `sss-mode.el` | Separate file is auto-loaded by `:files ("*.el")` recipe but adds complexity; inline preserves PACK-01 single-file requirement |
| `define-key evil-normal-state-map` | `map! :n` (Doom only) | For the evil operators themselves, use vanilla `evil-define-key` or `define-key` -- saves a Doom dependency in the core evil block |

**Installation:** No new packages needed. Evil and Doom are pre-existing dependencies of the user's environment. The sss-mode.el package itself remains zero-dependency.

---

## Architecture Patterns

### Recommended Project Structure

No new files. All Phase 6 code goes into:
```
emacs/
└── sss-mode.el    # Phase 6 adds two new top-level blocks at the bottom:
                   #   Block 1: (with-eval-after-load 'evil ...) -- operators + text objects
                   #   Block 2: (when (fboundp 'map!) ...) -- Doom leader/localleader bindings
```

The `:files ("*.el")` recipe means any new `.el` files in `emacs/` are auto-included. However, adding files just to split code is unnecessary given the size (sss-mode.el is ~640 lines; Phase 6 adds ~60-80 lines at most).

### Pattern 1: Evil Operator Definition

**What:** `evil-define-operator` macro creates an operator command. The body receives `beg` and `end` (buffer positions of the motion range) and calls existing region functions.

**When to use:** Any time you want a verb that acts on a motion in evil normal/visual state.

**Example (from official Evil docs and sss-doom.el source):**
```elisp
;; Source: https://evil.readthedocs.io/en/latest/extension.html
;; and verified from plugins/emacs/sss-doom.el
(evil-define-operator sss-evil-encrypt (beg end)
  "Evil operator to encrypt region between BEG and END."
  :motion evil-line
  (sss-encrypt-region beg end))

(evil-define-operator sss-evil-decrypt (beg end)
  "Evil operator to decrypt region between BEG and END."
  :motion evil-line
  (sss-decrypt-region beg end))

(evil-define-operator sss-evil-toggle (beg end)
  "Evil operator to toggle encryption at point or region."
  :motion evil-line
  (if (= beg end)
      (sss-toggle-at-point)
    (sss-encrypt-region beg end)))
```

Key option notes:
- `:motion evil-line` -- default motion if no motion follows (e.g. `ge<RET>` acts on current line)
- `(beg end)` -- always these two args for a standard region operator
- No `:type` needed; defaults work for character-wise operations

### Pattern 2: Evil Text Object Definition

**What:** `evil-define-text-object` + bind to `evil-inner-text-objects-map` / `evil-outer-text-objects-map`. Inner excludes delimiters, outer includes them.

**When to use:** Selecting a structured region for use with any operator (e.g. `vis` to select inner sss marker in visual mode, then encrypt it).

**Example (adapted from evil-args and sss-doom.el):**
```elisp
;; Source: https://evil.readthedocs.io/en/latest/extension.html
;; Verified pattern from plugins/emacs/sss-doom.el lines 165-192

(evil-define-text-object sss-inner-pattern (count &optional beg end type)
  "Inner text object: select content inside SSS marker braces."
  ;; Returns (START END) of the content inside {}, excluding delimiters
  (let ((bounds (sss--marker-at-point)))
    (when bounds
      (save-excursion
        (goto-char (car bounds))
        ;; Skip past the marker prefix (e.g. "\xe2\x8a\xa0{") to find {
        (when (re-search-forward "{" (cdr bounds) t)
          (let ((content-start (point))
                (content-end (save-excursion
                               (goto-char (cdr bounds))
                               (when (re-search-backward "}" (car bounds) t)
                                 (point)))))
            (when content-end
              (list content-start content-end))))))))

(evil-define-text-object sss-outer-pattern (count &optional beg end type)
  "Outer text object: select entire SSS marker including delimiters."
  (let ((bounds (sss--marker-at-point)))
    (when bounds
      (list (car bounds) (cdr bounds)))))

;; Register with evil's text object maps
(define-key evil-inner-text-objects-map "s" 'sss-inner-pattern)
(define-key evil-outer-text-objects-map "s" 'sss-outer-pattern)
```

### Pattern 3: Conditional Loading Guard

**What:** `with-eval-after-load` defers evil-specific code until evil is actually loaded, at which point the code runs unconditionally. This is the correct pattern for optional evil integration.

**When to use:** Any time a package optionally integrates with evil but must work without it.

```elisp
;; CORRECT: fires when evil loads, regardless of load order
;; Does NOT fire at all if evil is never loaded (vanilla Emacs)
(with-eval-after-load 'evil
  ;; evil-define-operator, evil-define-text-object, define-key on evil maps
  )

;; WRONG for top-level: only fires if evil is ALREADY loaded at this moment
(when (featurep 'evil)
  ;; order-dependent; breaks if sss-mode.el loads before evil
  )

;; WRONG for non-Doom: modulep! is a Doom-internal macro
(when (modulep! :editor evil)
  ;; void-function error in vanilla Emacs
  )
```

### Pattern 4: Doom map! Bindings

**What:** `map!` is Doom's syntactic sugar over `general.el`. It handles leader/localleader prefix setup, evil state restrictions, and deferred loading.

**When to use:** Only inside Doom context. Guard with `(when (fboundp 'map!) ...)` or `(with-eval-after-load 'doom-core ...)` to prevent errors in vanilla Emacs.

```elisp
;; Source: verified from plugins/emacs/sss-doom.el lines 58-97
;; and https://discourse.doomemacs.org/t/what-are-leader-and-localleader-keys/153

;; Global leader: SPC e prefix for project/key operations
(map! :leader
      (:prefix-map ("e" . "encryption")
       :desc "Encrypt region"    "e" #'sss-encrypt-region
       :desc "Decrypt region"    "d" #'sss-decrypt-region
       :desc "Toggle at point"   "t" #'sss-toggle-at-point
       :desc "Preview at point"  "v" #'sss-preview-at-point
       (:prefix ("p" . "project")
        :desc "Init project"     "i" #'sss-init
        :desc "Process project"  "p" #'sss-process)
       (:prefix ("k" . "keys")
        :desc "Generate keys"    "g" #'sss-keygen
        :desc "List keys"        "l" #'sss-keys-list)
       :desc "SSS menu"          "SPC" #'sss-dispatch))

;; Local leader: , e in sss-mode buffers (user's config sets doom-localleader-key to ",")
(map! :localleader
      :map sss-mode-map
      (:prefix ("e" . "sss")
       :desc "Encrypt region"    "e" #'sss-encrypt-region
       :desc "Decrypt region"    "d" #'sss-decrypt-region
       :desc "Toggle at point"   "t" #'sss-toggle-at-point
       :desc "Preview at point"  "v" #'sss-preview-at-point
       :desc "SSS menu"          "SPC" #'sss-dispatch))

;; Evil operator bindings in Doom (can also use map! :n)
;; Note: these shadow ge/gd/gt from evil-motion-state-map
(when (featurep 'evil)
  (map! :map evil-normal-state-map
        :desc "SSS encrypt operator" "ge" #'sss-evil-encrypt
        :desc "SSS decrypt operator" "gd" #'sss-evil-decrypt
        :desc "SSS toggle operator"  "gt" #'sss-evil-toggle))
```

Key map! syntax notes:
- `:leader` -- binds under doom-leader-key (SPC by default)
- `:localleader :map MODE-MAP` -- binds under doom-localleader-key for that mode
- `:prefix-map ("key" . "name")` -- creates a named prefix
- `:prefix ("key" . "name")` -- nested prefix within current prefix
- `:desc "description"` -- adds which-key description
- `:n` / `:v` -- normal / visual state (can also use :map evil-normal-state-map)

### Pattern 5: Two-Block Structure in sss-mode.el

The complete Phase 6 addition to `sss-mode.el` is two blocks at the bottom, before `(provide 'sss-mode)`:

```elisp
;;; Evil integration (EVIL-01, EVIL-02, EVIL-03)

(with-eval-after-load 'evil
  ;; Operators
  (evil-define-operator sss-evil-encrypt (beg end) ...)
  (evil-define-operator sss-evil-decrypt (beg end) ...)
  (evil-define-operator sss-evil-toggle (beg end) ...)
  ;; Key bindings: bind in evil-normal-state-map to shadow motion state ge/gd/gt
  (define-key evil-normal-state-map (kbd "ge") #'sss-evil-encrypt)
  (define-key evil-normal-state-map (kbd "gd") #'sss-evil-decrypt)
  (define-key evil-normal-state-map (kbd "gt") #'sss-evil-toggle)
  ;; Text objects
  (evil-define-text-object sss-inner-pattern ...)
  (evil-define-text-object sss-outer-pattern ...)
  (define-key evil-inner-text-objects-map "s" 'sss-inner-pattern)
  (define-key evil-outer-text-objects-map "s" 'sss-outer-pattern))

;;; Doom integration (DOOM-01, DOOM-02, DOOM-03)

(when (fboundp 'map!)
  (map! :leader
        (:prefix-map ("e" . "encryption") ...))
  (map! :localleader
        :map sss-mode-map ...))
```

### Anti-Patterns to Avoid

- **Using `(when (featurep 'evil) ...)` at top-level**: Order-dependent; breaks if sss-mode.el loads before evil (common in daemon mode / early init). Use `with-eval-after-load` instead.
- **Using `modulep!` outside Doom**: This macro is undefined in vanilla Emacs, causing a `void-function` error on load. Never use it in a package that claims "zero errors in vanilla Emacs."
- **Binding in `evil-motion-state-map`**: The existing `ge`, `gd`, `gt` are in motion state. Binding in normal state shadows them for normal-state commands without removing them from operator-pending state (where motions are needed). This is the correct approach per how evil works.
- **Not guarding Doom map! at all**: `map!` is undefined in vanilla Emacs. Without a guard, loading sss-mode.el outside Doom raises `void-function map!`.
- **Calling `(require 'sss)` or `(require 'sss-mode)` inside the evil block**: Circular dependency risk. The evil block is already inside sss-mode.el; functions are already defined. No `require` needed.
- **Using `:motion nil` on toggle operator**: The sss-doom.el source uses `:motion evil-line` as the default. Do not set `:motion nil` -- this forces users to always supply a motion, breaking `gt<RET>` for line-level toggle.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Operator that acts on motions | Custom key+region tracking | `evil-define-operator` macro | Handles all motion types, visual state, repeat (`.`), operator-pending state automatically |
| Text object boundary selection | Custom search functions | `evil-define-text-object` + `sss--marker-at-point` (already implemented) | Handles count, type, visual state integration |
| Leader key prefix setup | Custom prefix keymaps | `map!` with `:prefix-map` | Handles which-key integration, Doom module ordering, evil state restrictions |
| Conditional evil loading | Checking evil-version, evil-mode-active-p | `with-eval-after-load 'evil` | Standard Emacs deferred loading; idiomatic, load-order safe |

**Key insight:** All the underlying region operations (`sss-encrypt-region`, `sss-decrypt-region`, `sss-toggle-at-point`, `sss--marker-at-point`) are already implemented in Phase 5. Phase 6 is purely wiring -- operators call existing functions, no new encryption logic needed.

---

## Common Pitfalls

### Pitfall 1: Key Binding Conflict with ge/gd/gt

**What goes wrong:** `ge` (`evil-backward-word-end`), `gd` (`evil-goto-definition`), and `gt` (`evil-tab-next`) are default evil bindings in `evil-motion-state-map`. Binding `ge` as an operator in `evil-normal-state-map` will shadow it in normal state -- users lose `ge` as a backward word motion.

**Why it happens:** The ROADMAP explicitly specifies these key sequences (matching sss-doom.el source). This is a design choice, not a bug.

**How to avoid:** Accept this as the specified design. Document the conflict clearly in code comments. The operator bindings in `evil-normal-state-map` shadow (not replace) the motion bindings -- the motions still work in other states (visual, operator-pending, motion). The binding is mode-global, not sss-mode-local, which means `ge` means "encrypt" everywhere when evil is active. Consider whether scoping to sss-mode-map is preferable (see Open Questions).

**Warning signs:** Users complaining `ge` no longer moves backward; loss of `gd` (go-to-definition) in programming modes.

### Pitfall 2: Doom map! Called Before Doom is Initialized

**What goes wrong:** `(map! ...)` at the top level of sss-mode.el will fail with `void-function map!` in vanilla Emacs. Even in Doom, map! may not be defined at the time sss-mode.el is first loaded.

**Why it happens:** sss-mode.el may load early (via magic-mode-alist detecting a sealed file before Doom finishes initializing).

**How to avoid:** Wrap all `map!` calls in `(when (fboundp 'map!) ...)`. This is the same guard the existing `(when (require 'transient nil t) ...)` uses for the transient menu. Alternatively, use `(with-eval-after-load 'doom-core ...)`.

**Warning signs:** `Error in find-file-hook (sss--find-file-hook): Symbol's function definition is void: map!` on Doom startup.

### Pitfall 3: sss-doom.el Calls (require 'sss) and (require 'sss-ui) -- Functions Don't Exist

**What goes wrong:** The source `sss-doom.el` calls `(require 'sss)` and `(require 'sss-ui)` inside `sss--setup-doom-keybindings`. These are the old plugin packages that will be deleted in Phase 7. In the new sss-mode.el, these don't exist.

**Why it happens:** We're porting from the old multi-file plugin, not copying verbatim.

**How to avoid:** Never call `(require 'sss)` or `(require 'sss-ui)` in sss-mode.el. All needed functions are already defined in sss-mode.el at the point the evil/Doom blocks execute.

### Pitfall 4: Text Object Returning Wrong Format

**What goes wrong:** `evil-define-text-object` body must return a list `(BEG END)` -- not a cons cell `(BEG . END)`. Using the wrong return format causes evil to signal a range error.

**Why it happens:** `sss--marker-at-point` returns a cons cell `(BEG . END)`. You cannot pass this directly to evil's text object -- you must convert: `(list (car bounds) (cdr bounds))`.

**How to avoid:** Always `(list start end)` in text object bodies. Never `(cons start end)` or `(bounds)` directly.

**Warning signs:** `Wrong type argument: integer-or-marker-p, (1234 . 5678)` error when using text objects.

### Pitfall 5: sss-inner-pattern Fails When Point Is Not on a Marker

**What goes wrong:** `sss--marker-at-point` returns nil if point is not on an SSS marker. The text object body must handle nil gracefully -- evil expects nil return or a valid range, not an error.

**Why it happens:** Text objects can be invoked anywhere. Evil calls the body and expects nil (no object found) or `(BEG END)`.

**How to avoid:** Always guard with `(when bounds ...)` and return nil implicitly when no marker is found. Do not `(error ...)` or `(user-error ...)` from text objects -- that breaks operator-pending state.

---

## Code Examples

Verified patterns from official sources and sss-doom.el:

### Complete Evil Integration Block

```elisp
;; Source: evil.readthedocs.io/en/latest/extension.html + sss-doom.el lines 31-46
;;; Evil integration (EVIL-01, EVIL-02, EVIL-03)

(with-eval-after-load 'evil

  ;; Operators (EVIL-01, EVIL-02, EVIL-03)
  (evil-define-operator sss-evil-encrypt (beg end)
    "Evil operator to encrypt region between BEG and END.
Wraps the region in an open marker and seals it.
Example: `gew' encrypts the word under point."
    :motion evil-line
    (sss-encrypt-region beg end))

  (evil-define-operator sss-evil-decrypt (beg end)
    "Evil operator to decrypt sealed marker between BEG and END.
Example: `gdw' decrypts the sealed marker the word falls within."
    :motion evil-line
    (sss-decrypt-region beg end))

  (evil-define-operator sss-evil-toggle (beg end)
    "Evil operator to toggle encryption of the SSS marker at/in region.
When BEG equals END (point-based), calls `sss-toggle-at-point'.
When a range is given, encrypts the region.
Example: `gtis' toggles the inner SSS pattern at point."
    :motion evil-line
    (if (= beg end)
        (sss-toggle-at-point)
      (sss-encrypt-region beg end)))

  ;; Bind operators to ge/gd/gt in normal state.
  ;; NOTE: This shadows evil-motion-state-map bindings:
  ;;   ge = evil-backward-word-end (motion)
  ;;   gd = evil-goto-definition (motion)
  ;;   gt = evil-tab-next (when tab-bar available)
  ;; The original motions remain accessible in visual and operator-pending states.
  (define-key evil-normal-state-map (kbd "ge") #'sss-evil-encrypt)
  (define-key evil-normal-state-map (kbd "gd") #'sss-evil-decrypt)
  (define-key evil-normal-state-map (kbd "gt") #'sss-evil-toggle)

  ;; Text objects: `is' (inner sss) and `as' (outer sss)  (EVIL-03)
  ;; Usage: vis, dis, cis, yas -- select/delete/change/yank inner pattern content
  ;;        vas, das, cas, yas -- select/delete/change/yank whole pattern

  (evil-define-text-object sss-inner-pattern (count &optional beg end type)
    "Inner SSS text object: select content inside marker braces, excluding delimiters.
Example: on \\xe2\\x8a\\xa0{mysecret}, `is' selects `mysecret'."
    (let ((bounds (sss--marker-at-point)))
      (when bounds
        (save-excursion
          (goto-char (car bounds))
          (when (re-search-forward "{" (cdr bounds) t)
            (let ((content-start (point))
                  (content-end (save-excursion
                                 (goto-char (cdr bounds))
                                 (when (re-search-backward "}" (car bounds) t)
                                   (point)))))
              (when content-end
                (list content-start content-end))))))))

  (evil-define-text-object sss-outer-pattern (count &optional beg end type)
    "Outer SSS text object: select entire marker including prefix and braces.
Example: on \\xe2\\x8a\\xa0{mysecret}, `as' selects `\\xe2\\x8a\\xa0{mysecret}'."
    (let ((bounds (sss--marker-at-point)))
      (when bounds
        (list (car bounds) (cdr bounds)))))

  (define-key evil-inner-text-objects-map "s" 'sss-inner-pattern)
  (define-key evil-outer-text-objects-map "s" 'sss-outer-pattern))
```

### Complete Doom Integration Block

```elisp
;; Source: sss-doom.el lines 58-97 + discourse.doomemacs.org leader docs
;;; Doom integration (DOOM-01, DOOM-02, DOOM-03)
;; Guard with fboundp: map! is undefined in vanilla Emacs.

(when (fboundp 'map!)

  ;; Global leader: SPC e -- encryption prefix (DOOM-01)
  ;; Provides project and key management commands accessible everywhere
  (map! :leader
        (:prefix-map ("e" . "encryption")
         :desc "Encrypt region"   "e" #'sss-encrypt-region
         :desc "Decrypt region"   "d" #'sss-decrypt-region
         :desc "Toggle at point"  "t" #'sss-toggle-at-point
         :desc "Preview at point" "v" #'sss-preview-at-point
         :desc "SSS menu"         "SPC" #'sss-dispatch
         (:prefix ("p" . "project")
          :desc "Init project"    "i" #'sss-init
          :desc "Process project" "p" #'sss-process)
         (:prefix ("k" . "keys")
          :desc "Generate keys"   "g" #'sss-keygen
          :desc "List keys"       "l" #'sss-keys-list)))

  ;; Local leader: , e -- buffer-local operations in sss-mode (DOOM-02)
  ;; User's config: doom-localleader-key = ","
  ;; Binds to sss-mode-map so it only activates in sss buffers
  (map! :localleader
        :map sss-mode-map
        (:prefix ("e" . "sss")
         :desc "Encrypt region"   "e" #'sss-encrypt-region
         :desc "Decrypt region"   "d" #'sss-decrypt-region
         :desc "Toggle at point"  "t" #'sss-toggle-at-point
         :desc "Preview at point" "v" #'sss-preview-at-point
         :desc "SSS menu"         "SPC" #'sss-dispatch)))
```

### Vanilla Emacs Load Test Pattern

```elisp
;; To verify: no errors when loading sss-mode.el without evil or Doom
;; Run in a clean Emacs: emacs -Q --load /path/to/emacs/sss-mode.el
;; Expected: loads cleanly, (featurep 'evil) = nil, map! never called
;; Both with-eval-after-load blocks silently wait; fboundp 'map! = nil skips Doom block
```

---

## State of the Art

| Old Approach (sss-doom.el) | New Approach (sss-mode.el) | Reason |
|---------------------------|---------------------------|--------|
| Separate `sss-doom.el` file with Doom-specific loading | Inline blocks in `sss-mode.el` with guards | Preserves PACK-01 single-file requirement; recipe `:files ("*.el")` already loads all files in emacs/ but single-file is simpler |
| `(when (featurep 'evil) ...)` at top level | `(with-eval-after-load 'evil ...)` | `with-eval-after-load` is load-order safe; featurep at top level is fragile |
| `(require 'sss)` and `(require 'sss-ui)` inside Doom setup | No requires needed | Those packages are being deleted; all functions are in sss-mode.el already |
| `sss--setup-doom-keybindings` function called from `sss-doom-setup` | `(when (fboundp 'map!) ...)` block at top level | Simpler; map! is idempotent in Doom; no need for a setup function |
| Calls sss-pattern-at-point (old function) | Calls sss--marker-at-point (Phase 5 function) | sss--marker-at-point is the correct Phase 5 implementation |

**Deprecated/outdated from sss-doom.el:**
- `sss-doom-setup` / `sss--setup-doom-keybindings`: Unnecessary indirection; inline guards work.
- `(require 'sss)`, `(require 'sss-ui)`: Old plugin packages being removed in Phase 7.
- `sss-pattern-at-point`: Old function; use `sss--marker-at-point` from Phase 5.
- `sss-preview-secret-at-point`: Old function; use `sss-preview-at-point` from Phase 5.
- `sss-init-project`: Old function; use `sss-init` from sss-mode.el.
- `sss-generate-keypair`, `sss-list-keys`, `sss-show-pubkey`: Old functions; use `sss-keygen`, `sss-keys-list` from sss-mode.el.

---

## Open Questions

1. **Should ge/gd/gt be global or sss-mode-local?**
   - What we know: ROADMAP specifies `ge`, `gd`, `gt` in evil normal state globally. sss-doom.el binds them on `evil-normal-state-map` (global).
   - What's unclear: This shadows `evil-goto-definition` (`gd`) globally in all buffers, which is a significant loss for programming modes. Binding on `sss-mode-map` in normal state (via `evil-define-key 'normal sss-mode-map "ge" #'sss-evil-encrypt`) would be buffer-local -- only active in sss-mode buffers.
   - Recommendation: **Bind on `sss-mode-map` not globally.** Use `(evil-define-key 'normal sss-mode-map (kbd "ge") #'sss-evil-encrypt)` inside the `with-eval-after-load 'evil` block. This preserves `gd` for goto-definition in all other modes. The ROADMAP says "In evil normal state, `ge{motion}` encrypts..." without specifying global vs local. Local is strictly better UX.

2. **DOOM-03 requirement says `modulep!` -- but that's Doom-internal**
   - What we know: The requirement text says "loads only when `(modulep! :editor evil)` is available." But `modulep!` is undefined outside Doom (causes void-function error).
   - What's unclear: Was the requirement written with Doom-only context in mind, or does it intend "graceful degradation"?
   - Recommendation: Interpret DOOM-03 as "evil and Doom features are conditionally defined" (which is how the success criterion phrases it). Use `with-eval-after-load 'evil` for operators and `(when (fboundp 'map!) ...)` for Doom bindings. These achieve the same result without breaking vanilla Emacs.

3. **`is` text object key -- potential conflict with evil-surround or other packages?**
   - What we know: Doom loads evil-surround, evil-textobj-anyblock, and others that may use `s`. The existing Doom text objects documented for evil module are: a, B, c, f, g, i, j, k, q, u, x. `s` is not in the listed set.
   - What's unclear: Whether evil-surround uses `s` as a text object (it uses `s` as an operator in visual state, not as a text object key).
   - Recommendation: `s` for sss text objects is likely safe but cannot be 100% verified without testing. If conflict emerges, fallback key could be `S` (uppercase).

---

## Sources

### Primary (HIGH confidence)
- Evil official docs (evil.readthedocs.io/en/latest/extension.html) -- `evil-define-operator` and `evil-define-text-object` API
- Evil official source (`github.com/emacs-evil/evil/blob/master/evil-maps.el`) -- ge/gd/gt default bindings confirmed: `ge` = `evil-backward-word-end`, `gd` = `evil-goto-definition`, `gt` = `evil-tab-next` (all in `evil-motion-state-map`)
- `plugins/emacs/sss-doom.el` (in-repo source) -- verified operator definitions, Doom map! patterns, evil text object definitions used in the old plugin
- `emacs/sss-mode.el` (in-repo source, after Phase 5) -- confirmed available functions: `sss-encrypt-region`, `sss-decrypt-region`, `sss-toggle-at-point`, `sss--marker-at-point`, `sss-preview-at-point`, `sss-dispatch`, `sss-init`, `sss-process`, `sss-keygen`, `sss-keys-list`
- `/home/dsp/.config/doom/packages.el` -- confirmed `(package! sss-mode :recipe (:local-repo "..." :files ("*.el")))` -- all .el files in emacs/ are loaded
- `/home/dsp/.config/doom/+bindings.el` -- confirmed `(setq doom-localleader-key ",")` -- so localleader is `,` not `SPC m`
- `/home/dsp/.config/doom/init.el` -- confirmed `(evil +everywhere)` is enabled, so evil is present

### Secondary (MEDIUM confidence)
- Doom Emacs discourse (discourse.doomemacs.org/t/what-are-leader-and-localleader-keys/153) -- map! :leader/:localleader syntax and :prefix-map patterns
- Evil extension docs (evil.readthedocs.io/en/latest/keymaps.html) -- confirmed motion state bindings inherited by normal state
- evil-args package (github.com/wcsmith/evil-args) -- verified `(define-key evil-inner-text-objects-map "a" 'evil-inner-arg)` pattern for text object registration

### Tertiary (LOW confidence, needs validation)
- Various community sources on `featurep` vs `with-eval-after-load` timing -- general principle well-established but not from evil-specific official docs

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH -- Evil API verified from official docs; Doom patterns from source
- Architecture (single file, guard patterns): HIGH -- verified from existing codebase, official evil docs
- Key binding conflicts (ge/gd/gt): HIGH -- verified from evil-maps.el source
- Text object return format (list vs cons): HIGH -- verified from evil-args source and docs
- Doom map! syntax: MEDIUM -- verified from sss-doom.el and discourse; Doom docs are thin
- `is` text object key conflict: LOW -- cannot verify without running Doom with all plugins; no conflict found in documented evil text objects

**Research date:** 2026-02-21
**Valid until:** 2026-08-21 (evil API is stable; Doom map! syntax is stable; conflicts unlikely to change)
