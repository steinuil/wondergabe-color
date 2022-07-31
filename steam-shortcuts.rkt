#lang racket

(require "vdf.rkt"
         "steamgriddb.rkt"
         net/url)

(struct artwork [grid-hor ;; <appid>
                 grid-ver ;; <appid>p
                 hero     ;; <appid>_hero
                 logo])   ;; <appid>_logo

;; Shortcuts file: userdata/<userid>/config/shortcuts.vdf
;; Artwork dir: userdata/<userid>/config/grid

(define (list-shortcuts shortcuts-file)
  (define shortcuts
    (with-input-from-file shortcuts-file read-vdf))
  (for ([app (hash-values (hash-ref shortcuts "shortcuts"))])
    (define name (hash-ref app "AppName"))
    (define id (hash-ref app "appid"))
    '()))

(define api-key "")

(displayln
 (port->string
  (steamgriddb-search "HoloCure" #:api-key api-key)))

(displayln
 (port->string
  (steamgriddb-grids 5338844 #:api-key api-key)))