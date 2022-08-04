#lang racket/base

(require (for-syntax racket/base)
         racket/match
         racket/string)

(provide read-uint
         read-string0
         read-values
         seek-bytes)

(define (read-uint size in)
  (define b (read-bytes size in))
  (integer-bytes->integer b #f))

(define (read-string0 byte-size in)
  (string-trim (read-string byte-size in) "\0" #:repeat? #t))

(define (seek-bytes count in)
  (file-position in (+ (file-position in) count)))

(define (read-type type in)
  (match type
    ['u8 (read-byte in)]
    ['u16 (read-uint 2 in)]
    ['u32 (read-uint 4 in)]
    ['u64 (read-uint 8 in)]
    [(list 'bytes n)
     (read-bytes n in)]
    [(list 'string n)
     (read-string n in)]
    [(list 'string0 n)
     (read-string0 n in)]
    [(list 'pad n)
     (seek-bytes n in)]
    [(list 'custom fn)
     (fn in)]))

(define-syntax quote-field-type
  (syntax-rules ()
    [(quote-field-type (type qty))
     (list 'type qty)]
    [(quote-field-type type)
     'type]))

(define-syntax (read-value-field stx)
  (syntax-case stx ()
    [(read-value-field in name type)
     (if (equal? (syntax->datum #'name) '_)
         #'(read-type (quote-field-type type) in)
         #'(define name (read-type (quote-field-type type) in)))]))

(define-syntax read-values
  (syntax-rules ()
    [(read-values in [name type] ...)
     (begin
       (read-value-field in name type)
       ...)]))