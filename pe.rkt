#lang racket

(define (read-anyint-le byte-size)
  (lambda (in)
    (for/fold ([n 0])
              ([shift (build-list byte-size (lambda (x) (* x 8)))])
      (bitwise-ior n (arithmetic-shift (read-byte in) shift)))))

(define read-u16-le (read-anyint-le 2))
(define read-u32-le (read-anyint-le 4))
(define read-u64-le (read-anyint-le 8))

;(define-syntax read-values-le
;  (syntax-rules ()
;    [(read-values-le in [name byte-size] ...)
;     (begin
;       (define name ((read-anyint-le byte-size) in))
;       ...)]))

(define (read-string0 byte-size in)
  (string-trim (read-string byte-size in) "\0" #:repeat? #t))

(define (read-type type in)
  (match type
    ['u8 (read-byte in)]
    ['u16 (read-u16-le in)]
    ['u32 (read-u32-le in)]
    ['u64 (read-u64-le in)]
    [(list 'bytes n)
     (read-bytes n in)]
    [(list 'string n)
     (read-string n in)]
    [(list 'string0 n)
     (read-string0 n in)]
    [(list 'pad n)
     (discard-bytes n in)]
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

(define (discard-bytes n in)
  (for ([i (make-list n null)])
    (read-byte in)))

(define (read-image-data-directory in)
  (read-values in
    [virtual-address u32]
    [size            u32])
  (image-data-directory virtual-address size))

(struct image-data-directory [virtual-address size]
  #:transparent)

(struct image-section-header
  [name
   virtual-size
   virtual-address
   size-of-raw-data
   pointer-to-raw-data
   pointer-to-relocations
   pointer-to-line-numbers
   number-of-relocations
   number-of-line-numbers
   characteristics]
  #:transparent)

(struct resource-directory-table
  [characteristics
   time-date-stamp
   major-version
   minor-version
   number-of-name-entries
   number-of-id-entries]
  #:transparent)

(struct resource-directory-entry
  [name-offset
   integer-id
   data-entry-offset
   subdirectory-offset]
  #:transparent)

;; https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)#pe-file-resources
;; https://github.com/erocarrera/pefile/blob/master/pefile.py
(define (read-resource-directory-table in)
  (read-values in
    [characteristics        u32]
    [time-date-stamp        u32]
    [major-version          u16]
    [minor-version          u16]
    [number-of-name-entries u16]
    [number-of-id-entries   u16])

  (resource-directory-table
   characteristics
   time-date-stamp
   major-version
   minor-version
   number-of-name-entries
   number-of-id-entries))

;; MZ/PE documentation:
;; https://wiki.osdev.org/MZ
;; https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
(define (read-pe in)
  (define (raise-invalid) (raise-argument-error 'in "pe-exe?" in))

  (when (not (equal? (read-bytes 2 in) #"MZ"))
    (raise-invalid))

  (read-values in
    [_ (pad 58)]
    [pe-header-start u32]) ;; e_lfanew

  ;; Skip to PE file header
  (discard-bytes (- pe-header-start 64) in)

  (when (not (equal? (read-bytes 4 in) #"PE\0\0"))
    (raise-invalid))

  ;; COFF file header
  (read-values in
    [machine                 u16]
    [number-of-sections      u16]
    [time-date-stamp         u32]
    [pointer-to-symbol-table u32]
    [number-of-symbols       u32]
    [size-of-optional-header u16]
    [characteristics         u16])

  ;; Optional header standard fields
  (define image-format
    (case (read-u16-le in)
      [(#x10b) 'pe32]
      [(#x20b) 'pe32+]
      [else (raise-invalid)]))

  (read-values in
    [major-linker-version       u8]
    [minor-linker-version       u8]
    [size-of-code               u32]
    [size-of-initialized-data   u32]
    [size-of-uninitialized-data u32]
    [address-of-entry-point     u32]
    [base-of-code               u32]
    [base-of-data               (custom (lambda (in)
                                          (case image-format
                                            [(pe32) (read-u32-le in)]
                                            [(pe32+) (void)])))])

  ;; Optional header Windows-specific fields
  (define read-size-field
    (case image-format
      [(pe32)  read-u32-le]
      [(pe32+) read-u64-le]))

  (read-values in
    [image-base                     (custom read-size-field)]
    [section-alignment              u32]
    [file-alignment                 u32]
    [major-operating-system-version u16]
    [minor-operating-system-version u16]
    [major-image-version            u16]
    [minor-image-version            u16]
    [major-subsystem-version        u16]
    [minor-subsystem-version        u16]
    [win32-version-value            u32]
    [size-of-image                  u32]
    [size-of-headers                u32]
    [check-sum                      u32]
    [subsystem                      u16]
    [dll-characteristics            u16]
    [size-of-stack-reserve          (custom read-size-field)]
    [size-of-stack-commit           (custom read-size-field)]
    [size-of-heap-reserve           (custom read-size-field)]
    [size-of-heap-commit            (custom read-size-field)]
    [loader-flags                   u32]
    [number-of-rva-and-sizes        u32])

  ;; Optional header data directories
  (read-values in
    [export-table            (custom read-image-data-directory)]
    [import-table            (custom read-image-data-directory)]
    [resource-table          (custom read-image-data-directory)]
    [exception-table         (custom read-image-data-directory)]
    [certificate-table       (custom read-image-data-directory)]
    [base-relocation-table   (custom read-image-data-directory)]
    [debug                   (custom read-image-data-directory)]
    [architecture            (custom read-image-data-directory)]
    [global-ptr              (custom read-image-data-directory)]
    [lts-table               (custom read-image-data-directory)]
    [load-config-table       (custom read-image-data-directory)]
    [bound-import            (custom read-image-data-directory)]
    [iat                     (custom read-image-data-directory)]
    [delay-import-descriptor (custom read-image-data-directory)]
    [clr-runtime-header      (custom read-image-data-directory)]
    [_ (pad 8)])

  ;; Section headers
  (define sections
    (for/list ([idx (in-range number-of-sections)])
      (read-values in
        [name                    (string0 8)]
        [virtual-size            u32]
        [virtual-address         u32]
        [size-of-raw-data        u32]
        [pointer-to-raw-data     u32]
        [pointer-to-relocations  u32]
        [pointer-to-line-numbers u32]
        [number-of-relocations   u16]
        [number-of-line-numbers  u16]
        [characteristics         u32])

      (image-section-header
       name
       virtual-size
       virtual-address
       size-of-raw-data
       pointer-to-raw-data
       pointer-to-relocations
       pointer-to-line-numbers
       number-of-relocations
       number-of-line-numbers
       characteristics)))

  (define here (+ pe-header-start
                  24 ;; Magic number + COFF file header
                  size-of-optional-header
                  (* number-of-sections 40)))

  (define resource-section-offset
    (image-section-header-pointer-to-raw-data
     (findf (lambda (h)
              (equal? (image-section-header-name h)
                      ".rsrc"))
            sections)))
  
  (discard-bytes (- resource-section-offset here) in)

  ;; https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)#pe-file-resources
  (define x
    (read-resource-directory-table in))

  (define name-entries
    (for/list ([idx (in-range (resource-directory-table-number-of-name-entries x))])
      (read-values in
        [name-offset         u32]
        [integer-id          u32]
        [data-entry-offset   u32]
        [subdirectory-offset u32])

      (resource-directory-entry
       name-offset
       integer-id
       data-entry-offset
       (bitwise-and subdirectory-offset #x7fffffff))))

  (define id-entries
    (for/list ([idx (in-range (resource-directory-table-number-of-id-entries x))])
      (read-values in
        [name-offset         u32]
        [integer-id          u32]
        [data-entry-offset   u32]
        [subdirectory-offset u32])

      (resource-directory-entry
       name-offset
       integer-id
       data-entry-offset
       (bitwise-and subdirectory-offset #x7fffffff))))

  (displayln (read-resource-directory-table in))
  
  (list name-entries id-entries))

(call-with-input-file "C:\\Games\\AM2R\\AM2RLauncher.exe" read-pe)