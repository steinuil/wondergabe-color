#lang racket

(require racket/path)

(define hex-digits "0123456789abcdef")
(define (byte->hex-string b)
  (string (string-ref hex-digits (arithmetic-shift b -4))
          (string-ref hex-digits (bitwise-and b #xf))))

(define (bytes->hex-string bytes)
  (build-string (bytes-length bytes)
                (lambda (i)
                  (if (= (modulo i 2) 0)
                      (string-ref hex-digits (arithmetic-shift (bytes-ref bytes (quotient i 2)) -4))
                      (string-ref hex-digits (bitwise-and (bytes-ref bytes (quotient i 2)) #xf))))))

#;(let traverse-directory ([dir "C:\\Program Files (x86)"])
  (for ([path (in-directory dir)])
    (case (file-or-directory-type path)
      [(directory) (traverse-directory path)]
      [(file) (when (equal? (path-get-extension path) #".exe")
                (with-handlers ([exn:fail? (lambda (exn) (void))])
                  (displayln (bytes->hex-string (call-with-input-file path (lambda (in) (extract-icon-from-pe in null)))))))])))