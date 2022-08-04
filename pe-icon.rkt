#lang racket/base

(require (for-syntax racket/base)
         racket/match
         racket/port
         racket/string)

(provide extract-icon-from-pe)


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


(define (entry-is-leaf? child-offset)
  (= (bitwise-and child-offset #x80000000) 0))

(define (child-offset->directory-offset child-offset)
  (bitwise-and child-offset #x7fffffff))

(define (entry-is-icon? name)
  (= (bitwise-and name #xFFFF) 3))


(define (find-icon-data-entry offset in)
  (read-values in
    [_                      (pad 12)]
    [number-of-name-entries u16]
    [number-of-id-entries   u16])

  (seek-bytes (* 8 number-of-name-entries) in)

  (let read-entries ([entries-read 1])
    (when (> entries-read number-of-id-entries)
      ;; No icon
      (raise-argument-error 'in "pe-exe-with-icon?" in))

    (read-values in
      [name         u32]
      [child-offset u32])

    (if (entry-is-icon? name)
        (begin
          (file-position in (+ offset (child-offset->directory-offset child-offset)))

          ;; Descend the tree and read the first entry of each node until we find a leaf
          ;; FIXME probably doesn't work for all exe (Firefox doesn't work)
          (let descend-tree ()
            (read-values in
              [_                      (pad 12)]
              [number-of-name-entries u16]
              [number-of-id-entries   u16])

            (seek-bytes (* 8 number-of-name-entries) in)

            (read-values in
              [name         u32]
              [child-offset u32])

            (if (entry-is-leaf? child-offset)
                child-offset
                (begin
                  (file-position in (+ offset (child-offset->directory-offset child-offset)))
                  (descend-tree)))))
        (read-entries (+ entries-read 1)))))


(define (extract-icon-from-pe in out)
  (define (raise-invalid) (raise-argument-error 'in "pe-exe?" in))

  (when (not (equal? (read-bytes 2 in) #"MZ"))
    (raise-invalid))

  ;; Skip other fields of IMAGE_DOS_HEADER
  (file-position in 60)

  ;; Read e_lfanew
  (read-values in
    [pe-header-start u32])

  ;; Skip to COFF file header
  (file-position in pe-header-start)

  (when (not (equal? (read-bytes 4 in) #"PE\0\0"))
    (raise-invalid))

  ;; COFF file header
  (read-values in
    [_                       (pad 2)]
    [number-of-sections      u16]
    [_                       (pad 12)]
    [size-of-optional-header u16]
    [_                       (pad 2)])

  (when (= size-of-optional-header 0)
    ;; This might be an object file, not an exe
    (raise-invalid))

  ;; Skip the optional header
  (seek-bytes size-of-optional-header in)

  ;; Read section headers until we find the .rsrc section
  (define-values (resource-section-offset resource-section-virtual-address)
    (let read-sections ([sections-read 1])
      (when (> sections-read number-of-sections)
        ;; Executable doesn't contain a .rsrc section
        (raise-invalid))

      (read-values in
        [name                (string0 8)]
        [_                   (pad 4)]
        [virtual-address     u32]
        [_                   (pad 4)]
        [pointer-to-raw-data u32]
        [_                   (pad 16)])

      (if (equal? name ".rsrc")
          (values pointer-to-raw-data virtual-address)
          (read-sections (+ sections-read 1)))))

  ;; Jump to the resource section
  (file-position in resource-section-offset)

  ;; Search the icon data entry in the directory tree
  (define icon-data-entry-offset (find-icon-data-entry resource-section-offset in))

  ;; Seek to the icon data entry
  (file-position in (+ resource-section-offset icon-data-entry-offset))

  (read-values in
    [icon-data-rva u32]
    [icon-size     u32]
    [_             (pad 8)])

  ;; Seek to the actual icon data
  (define icon-data-offset (- icon-data-rva resource-section-virtual-address))
  (file-position in (+ resource-section-offset icon-data-offset))

  (copy-port (make-limited-input-port in icon-size) out))