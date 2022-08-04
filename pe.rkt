#lang racket

(require "read-values.rkt")

(struct image-data-directory
  [virtual-address
   size]
  #:transparent)

(define (read-image-data-directory in)
  (read-values in
    [virtual-address u32]
    [size            u32])
  (image-data-directory virtual-address size))

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
   name-entries
   id-entries]
  #:transparent)

(struct resource-directory-entry
  [name data-offset child]
  #:transparent)

(define (resource-directory-entry-id entry)
  (bitwise-and (resource-directory-entry-name entry) #xFFFF))


;; The resource directory tree is generally laid out like this:
;;
;;   +--- Tree depth
;;   v
;; +---+--------------+
;; | 0 | table #1     |
;; |   | # of entries | --+ table #1 entries
;; |   +--------------+   |
;; |   | entry #1     | <-+
;; |   | data offset  | --|--+ entry #1 child directory
;; |   +--------------+   |  |
;; |   | entry #2     | <-+  |
;; |   | data offset  | -----|--------------------------+ entry #2 child directory
;; +---+--------------+      |                          |
;; | 1 | table #2     | <----+                          |
;; |   | # of entries | --+ table #2 entries            |
;; |   +--------------+   |                             |
;; |   | entry #3     | <-+                             |
;; |   | offset       | ----+ entry #3 child directory  |
;; +---+--------------+     |                           |
;; | 2 | table #3     | <---+                           |
;; |   | # of entries | --+ table #3 entries            |
;; |   +--------------+   |                             |
;; |   | entry #4     | <-+                             |
;; |   | data offset  |                                 |
;; +---+--------------+                                 |
;; | 1 | table #4     | <-------------------------------+
;; |   | # of entries |
;; .   .              .
;;
;; Which defines this tree:
;; (table #1 (entry #1 (table #2 (entry #3 (table #3 (entry #4))))
;;                     (table #4 ...)))
;;
;; Generally the first table 
(define (read-resource-directory-table resource-section-offset in)
  (read-values in
    [characteristics        u32]
    [time-date-stamp        u32]
    [major-version          u16]
    [minor-version          u16]
    [number-of-name-entries u16]
    [number-of-id-entries   u16])

  (define name-entries-
    (for/list ([_ (in-range number-of-name-entries)])
      (read-values in
        [name         u32]
        [child-offset u32])
      (cons name child-offset)))

    (define id-entries-
      (for/list ([_ (in-range number-of-id-entries)])
        (read-values in
          [name         u32]
          [child-offset u32])
        (cons name child-offset)))

  (define (resource-directory-entry-has-child? entry)
    (> (bitwise-and (cdr entry) #x80000000) 0))

  (define (resource-directory-entry-child-offset entry)
    (bitwise-and (cdr entry) #x7fffffff))

  (define name-entries
    (for/list ([entry- name-entries-])
      (if (resource-directory-entry-has-child? entry-)
          (begin
            (file-position in (+ resource-section-offset
                                 (resource-directory-entry-child-offset entry-)))
            (resource-directory-entry
             (car entry-)
             #f
             (read-resource-directory-table resource-section-offset in)))
          (resource-directory-entry (car entry-) (cdr entry-) #f))))

  (define id-entries
    (for/list ([entry- id-entries-])
      (if (resource-directory-entry-has-child? entry-)
          (begin
            (file-position in (+ resource-section-offset
                                 (resource-directory-entry-child-offset entry-)))
            (resource-directory-entry
             (car entry-)
             #f
             (read-resource-directory-table resource-section-offset in)))
          (resource-directory-entry (car entry-) (cdr entry-) #f))))

  (resource-directory-table
   characteristics
   time-date-stamp
   major-version
   minor-version
   name-entries
   id-entries))


;; MZ/PE documentation:
;; https://wiki.osdev.org/MZ
;; https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
;; https://blog.kowalczyk.info/articles/pefileformat.html
;; https://cocomelonc.github.io/tutorial/2021/10/31/windows-shellcoding-3.html
(define (read-pe in)
  (define (raise-invalid) (raise-argument-error 'in "pe-exe?" in))

  (when (not (equal? (read-bytes 2 in) #"MZ"))
    (raise-invalid))

  (read-values in
    [_ (pad 58)]
    [pe-header-start u32]) ;; e_lfanew

  ;; Skip to PE file header
  (file-position in pe-header-start)

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
    (case (read-uint 2 in)
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
                                            [(pe32) (read-uint 4 in)]
                                            [(pe32+) #f])))])

  ;; Optional header Windows-specific fields
  (define (read-size-field in)
    (case image-format
      [(pe32)  (read-uint 4 in)]
      [(pe32+) (read-uint 8 in)]))

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

  (define resource-section-offset
    (image-section-header-pointer-to-raw-data
     (findf (lambda (h)
              (equal? (image-section-header-name h)
                      ".rsrc"))
            sections)))
  (when (not resource-section-offset)
    (raise-invalid))

  (file-position in resource-section-offset)

  (define resource-directory-tree
    (read-resource-directory-table resource-section-offset in))

  (pretty-print resource-directory-tree))

(call-with-input-file "C:\\Program Files\\Firefox Developer Edition\\updated\\firefox.exe" read-pe)
;(call-with-input-file "C:\\Games\\AM2R\\AM2RLauncher.exe" read-pe)