#lang racket/base

(require net/url
         racket/struct)

(provide steamgriddb-search
         steamgriddb-game
         steamgriddb-grids)

(define base-url "https://www.steamgriddb.com/api/v2")

(define (get path
             #:api-key api-key
             #:query [query '()])
  (define req-url
    (struct-copy url (string->url (string-append base-url path))
                 [query query]))
  (get-pure-port req-url
                 (list (string-append "Authorization: Bearer " api-key))))

(define (steamgriddb-search term #:api-key api-key)
  (get (string-append "/search/autocomplete/" term)
       #:api-key api-key))

(define (steamgriddb-game id #:api-key api-key)
  (get (string-append "/games/id/" (number->string id))
       #:api-key api-key))

(define (steamgriddb-grids id #:api-key api-key)
  (get (string-append "/grids/game/" (number->string id))
       #:api-key api-key))