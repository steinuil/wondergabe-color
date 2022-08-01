#lang racket

(require "vdf.rkt"
         "steamgriddb.rkt"
         net/url
         racket/path)

(struct steam-shortcut
  [appid
   name
   grid-hor
   grid-ver
   grid-hero
   grid-logo]
  #:transparent)

;; Shortcuts file: userdata/<userid>/config/shortcuts.vdf
;; Artwork dir: userdata/<userid>/config/grid

(define (list-shortcuts steam-dir userid)
  (define config-path
    (simplify-path (build-path steam-dir "userdata" (number->string userid) "config")))
  (define shortcuts-file (build-path config-path "shortcuts.vdf"))
  (define grid-dir (build-path config-path "grid"))

  (define shortcuts (with-input-from-file shortcuts-file read-vdf))

  (for/list ([(idx app) (hash-ref shortcuts "shortcuts")])
    (define name (hash-ref app "AppName"))
    (define appid (hash-ref app "appid"))

    (for/fold ([s (steam-shortcut appid name null null null null)])
              ([file (in-directory grid-dir)])
      (define fname (path->string (file-name-from-path (path-replace-extension file #""))))
      (cond
        [(equal? fname (number->string appid))
         (struct-copy steam-shortcut s [grid-hor file])]
        [(equal? fname (string-append (number->string appid) "p"))
         (struct-copy steam-shortcut s [grid-ver file])]
        [(equal? fname (string-append (number->string appid) "_hero"))
         (struct-copy steam-shortcut s [grid-hero file])]
        [(equal? fname (string-append (number->string appid) "_logo"))
         (struct-copy steam-shortcut s [grid-logo file])]
        [else s]))))

;(define api-key "")

;(displayln
; (port->string
;  (steamgriddb-search "HoloCure" #:api-key api-key)))

;(displayln
; (port->string
;  (steamgriddb-grids 5338844 #:api-key api-key)))

(pretty-print (list-shortcuts "C:\\Program Files (x86)\\Steam" 63802008))