#lang racket/base

;; Read and write binary VDF files.

(require racket/contract)

(provide binary-vdf-map?
         (contract-out
          [read-binary-vdf (->* () (input-port?) binary-vdf-map?)]
          [write-binary-vdf (->* (binary-vdf-map?) (output-port?) void?)]))

(define binary-vdf-value?
  (flat-rec-contract vdf-value
                     (hash/c string? vdf-value #:flat? #t)
                     string?
                     flonum?
                     exact-integer?))

(define binary-vdf-map?
  (hash/c string? binary-vdf-value? #:flat? #t))

(define map-tag 0)
(define string-tag 1)
(define int-tag 2)
(define float-tag 3)
(define end-of-map-tag 8)

(define (read-binary-vdf-string in)
  (define (loop str)
    (define char (read-char in))
    (if (eq? char #\nul)
        str
        (loop (string-append str (string char)))))
  (loop ""))

(define (read-binary-vdf-int in)
  (integer-bytes->integer (read-bytes 4) #t))

(define (read-binary-vdf-float in)
  (floating-point-bytes->real (read-bytes 4)))

(define (read-binary-vdf-map in)
  (define (loop m)
    (define tag (read-byte in))
    (if (= tag end-of-map-tag)
        m
        (let* ([name (read-binary-vdf-string in)]
               [val (cond
                      [(= tag map-tag)
                       (read-binary-vdf-map in)]
                      [(= tag string-tag)
                       (read-binary-vdf-string in)]
                      [(= tag int-tag)
                       (read-binary-vdf-int in)]
                      [(= tag float-tag)
                       (read-binary-vdf-float in)]
                      [else
                       (raise-argument-error 'in "vdf-tag?" tag)])])
          (loop (hash-set m name val)))))
  (loop #hash()))

(define (read-binary-vdf [in (current-input-port)])
  (read-binary-vdf-map in))

(define (write-binary-vdf-string str out)
  (write-string str out)
  (write-char #\nul out))

(define (write-binary-vdf-int n out)
  (write-bytes (integer->integer-bytes n 4 #t)))

(define (write-binary-vdf-float n out)
  (write-bytes (real->floating-point-bytes n 4)))

(define (write-binary-vdf-map map out)
  (for ([(key val) map])
    (cond
      [(hash? val)
       (write-byte map-tag out)
       (write-binary-vdf-string key out)
       (write-binary-vdf-map val out)]
      [(string? val)
       (write-byte string-tag out)
       (write-binary-vdf-string key out)
       (write-binary-vdf-string val out)]
      [(exact-integer? val)
       (write-byte int-tag out)
       (write-binary-vdf-string key out)
       (write-binary-vdf-int val out)]
      [(flonum? val)
       (write-byte float-tag out)
       (write-binary-vdf-string key out)
       (write-binary-vdf-float val out)]
      [else
       (raise-argument-error 'map "binary-vdf-value?" val)]))
  (write-byte end-of-map-tag out))

(define (write-binary-vdf m [out (current-output-port)])
  (write-binary-vdf-map m out))

(module+ test
  (require rackunit
           rackcheck
           racket/port
           racket/flonum)

  (define gen:string-without-null
    (gen:string
     (gen:filter gen:char (lambda (c) (not (eq? c #\nul))))))

  (define gen:int64
    (gen:integer-in -2147483648 2147483647))

  (define gen:float
    (gen:map gen:real (lambda (f) (flsingle f))))

  (define gen:binary-vdf-map
    (gen:delay
     (gen:bind
      gen:string-without-null
      (lambda (key)
        (gen:hash
         key
         (gen:choice gen:int64
                     gen:float
                     gen:string-without-null
                     gen:binary-vdf-map))))))

  (check-property
   (property ([vdf-map gen:binary-vdf-map])
     (define serialized (with-output-to-bytes (lambda () (write-binary-vdf vdf-map))))
     (define deserialized (with-input-from-bytes serialized (lambda () (read-binary-vdf))))
     (check-equal? vdf-map deserialized))))
