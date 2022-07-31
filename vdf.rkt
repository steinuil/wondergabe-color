#lang racket/base

(provide read-vdf
         write-vdf)

(define (read-vdf-string in)
  (define (loop str)
    (define char (read-char in))
    (if (eq? char #\nul)
        str
        (loop (string-append str (string char)))))
  (loop ""))

(define (read-vdf-int in)
  (define b0 (read-byte in))
  (define b1 (read-byte in))
  (define b2 (read-byte in))
  (define b3 (read-byte in))
  (bitwise-ior b0
               (arithmetic-shift b1 8)
               (arithmetic-shift b2 16)
               (arithmetic-shift b3 24)))

(define (read-vdf-map in)
  (define (loop m)
    (define tag (read-byte in))
    (if (= tag 8)
        m
        (let* ([name (read-vdf-string in)]
               [val (case tag
                      [(0) (read-vdf-map in)]
                      [(1) (read-vdf-string in)]
                      [(2) (read-vdf-int in)]
                      [else (raise-argument-error 'in "vdf-tag?" tag)])])
          (loop (hash-set m name val)))))
  (loop #hash()))

(define (read-vdf [in (current-input-port)])
  (read-vdf-map in))

(define (write-vdf-string str out)
  (write-string str out)
  (write-char #\nul out))

(define (write-vdf-int n out)
  (write-byte (bitwise-and n #xFF) out)
  (write-byte (bitwise-and (arithmetic-shift n -8) #xFF) out)
  (write-byte (bitwise-and (arithmetic-shift n -16) #xFF) out)
  (write-byte (bitwise-and (arithmetic-shift n -24) #xFF) out))

(define (vdf-value? val)
  (or (hash? val)
      (string? val)
      (exact-integer? val)))

(define (write-vdf-map map out)
  (for ([(key val) map])
    (cond
      [(hash? val)
       (write-byte 0 out)
       (write-vdf-string key out)
       (write-vdf-map val out)]
      [(string? val)
       (write-byte 1 out)
       (write-vdf-string key out)
       (write-vdf-string val out)]
      [(exact-integer? val)
       (write-byte 2 out)
       (write-vdf-string key out)
       (write-vdf-int val out)]
      [else (raise-argument-error 'map "vdf-value?" val)]))
  (write-byte 8 out))

(define (write-vdf m [out (current-output-port)])
  (write-vdf-map m out))