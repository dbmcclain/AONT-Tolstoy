
(in-package :ecc-crypto-b571)

;; AONT -- All Or Nothing Transformation
;; ---------------------------------------------------------------

(defun aont-ctr-ecb-enc-dec (key ivec ovec nel)
  (declare (type (vector (unsigned-byte 8)) key ivec ovec)
           (type fixnum nel))
  
  (let ((cvec  (make-array 16
                           :element-type '(unsigned-byte 8)
                           :initial-element 0))
        (idvec (make-array 0
                           :element-type '(unsigned-byte 8)
                           :displaced-to ivec
                           :adjustable   t))
        (odvec (make-array 0
                           :element-type '(unsigned-byte 8)
                           :displaced-to ovec
                           :adjustable   t))
        (ecb   (make-ecb-cipher :aes key)))
    
    (declare (type (simple-array (unsigned-byte 8) (16)) cvec)
             (type (vector (unsigned-byte 8)) idvec odvec)
             (dynamic-extent cvec idvec odvec ecb))

    (loop for off from 0 below nel by 16 do
          (let* ((nb    (min 16 (- nel off)))
                 (idvec (adjust-array idvec nb
                                      :displaced-to ivec
                                      :displaced-index-offset off))
                 (odvec (adjust-array odvec nb
                                      :displaced-to ovec
                                      :displaced-index-offset off)))
            
            (declare (dynamic-extent nb idvec odvec)
                     (type fixnum nb)
                     (type (vector (unsigned-byte 8)) idvec odvec))
            
            (replace cvec (convert-int-to-nbytes off 4) :start1 12)
            (safe-encrypt-in-place ecb cvec)
            (map-into odvec 'logxor cvec idvec)))
    ))

(defconstant $aont-canary$
  (uuid:uuid-to-byte-array  #/uuid/{6F7C24A8-1154-11E5-A006-129ADD578F77}))

(defun aont-transform (vec)
  (let* ((nel    (length vec))
         (cnel   (+ nel 16))
         (ovec   (make-cipher-block (+ cnel 32)))
         (key    (ctr-drbg 256)))

    
    ;;
    ;; encrypt the vector and accumulate the hash of the encryption
    ;;
    (replace ovec vec)
    (replace ovec $aont-canary$ :start1 nel)
    (aont-ctr-ecb-enc-dec key ovec ovec cnel)
    ;;
    ;; xor the hash with the key
    ;; storing the xor sum at the tail of the output
    ;;
    (let ((odvec (make-displaced-cipher-block ovec cnel 32)))
      (map-into odvec 'logxor
                key
                (ironclad:digest-sequence :sha256 ovec
                                          :end cnel)))
    
    ovec))


(defun aont-untransform (vec)
    
    (let* ((nel  (length vec))
           (onel (- nel 32))
           (ovec (make-cipher-block onel)))
      ;;
      ;; compute the hash of the body, xor with final 32 bytes
      ;; to find the key, and then create a cipher with that key
      ;;
      (aont-ctr-ecb-enc-dec 
       (let ((key (make-cipher-block 32)))
         (map-into key 'logxor
                   (make-displaced-cipher-block vec onel 32)
                   (ironclad:digest-sequence :sha256 vec
                                             :end onel))
         key)
       vec ovec onel)

      (unless (every '=
                     $aont-canary$
                     (subseq ovec (- onel 16)))
        (error "AONT: corrupt transform"))

      ovec))


;; ------------------------------------------------------------

(defun file-vector (fname)
  (with-open-file (f fname
                     :direction :input
                     :element-type '(unsigned-byte 8))
    (let* ((nel (file-length f))
           (vec (make-cipher-block nel)))
      (read-sequence vec f)
      vec)))

;; ------------------------------------------------------------
;; for LZW Compression of plaintext

(defun cvt-to-octets (v)
  ;; convert vector of integers to vector of octets using 7-bit
  ;; encodings so that numbers >= 128 become a sequence of 7-bit
  ;; sections with hi-bit set until the final section.  If bit pattern
  ;; of number is: #b1XXX XXXX YYY YYYY ZZZ ZZZZ, then output becomes
  ;; the sequence: #b1XXX XXXX #b1YYY YYYY #b0ZZZ ZZZZ
  (ubstream:with-output-to-ubyte-stream (s)
    (loop for x across v do
          (cond ((> x 127)
                 (write-sequence
                  (um:nlet-tail iter ((x     x)
                                      (hibit 0)
                                      (ans   nil))
                    (let ((ans (cons (logior hibit (logand x 127))
                                     ans)))
                      (if (> x 127)
                          (iter (ash x -7) #x80 ans)
                        ans)) )
                  s))
                
                (t (write-byte x s))))
    s))

(defun cvt-from-octets (v)
  ;; convert vector of octets from 7-bit encodings to vector of integers.
  ;; 7-bit values remain as they are. A sequence of octets with hi-bit set
  ;; indicate an integer encoding in 7-bit sections.
  ;; the sequence: #b1XXX XXXX #b1YYY YYYY #b0ZZZ ZZZZ becomes the integer
  ;; with bit pattern: #b1XXX XXXX YYY YYYY ZZZ ZZZZ
  (let ((acc 0)
        (ans (make-empty-vector 't)))
    (loop for x across v do
          (cond ((> x 127)
                 (setf acc (logior (ash acc 7) (logand x 127))))
                
                ((zerop acc)
                 (vector-append1 ans x))
                
                (t
                 (vector-append1 ans
                                 (logior (ash acc 7) x))
                 (setf acc 0))
                ))
    ans))

;; ----------------------------------------------------------------

(defun write-16u (w s)
  (write-byte (ldb (byte 8 8) w) s)
  (write-byte (ldb (byte 8 0) w) s))

(defun read-16u (s)
  (let* ((b1 (read-byte s))
         (b2 (read-byte s)))
    (dpb b1 (byte 8 8) (dpb b2 (byte 8 0) 0))))

(defun write-32u (w s)
  (write-16u (ldb (byte 16 16) w) s)
  (write-16u (ldb (byte 16  0) w) s))

(defun read-32u (s)
  (let* ((w1 (read-16u s))
         (w2 (read-16u s)))
    (dpb w1 (byte 16 16) (dpb w2 (byte 16 0) 0))))

(defun write-chunk (v s)
  (let ((vc (cvt-to-octets (lzw-compress v))))
    (write-32u (length vc) s)
    (write-sequence vc s)))

(defun read-chunk (s)
  (let* ((nel (read-32u s))
         (v   (make-array nel
                          :element-type '(unsigned-byte 8))))
    (read-sequence v s)
    (lzw-decompress (cvt-from-octets v))))

(defun write-compression (v s)
  (let ((vs (um:group v 65536)))
    (write-32u (length vs) s)
    (dolist (v vs)
      (write-chunk v s)) ))

(defun read-compression (s)
  (let* ((nvs (read-32u s))
         (v   #()))
    (loop repeat nvs do
          (setf v (concatenate 'vector v (read-chunk s))))
    v))
           
#|
(ubstream:with-output-to-ubyte-stream (s)
  (let* ((v (file-vector "aont.exe")))
    (write-compression v s)))

(let* ((str (hcl:file-string "VTuning/crypto/tools/aont.lisp"))
       (h   (huffman-encode (map 'vector 'char-code str))))
  (map 'string 'code-char (huffman-decode (first h) (third h) (second h))))


(let* ((str (hcl:file-string "VTuning/crypto/tools/aont.lisp"))
       (lzstr (lzw-compress str))
       (h   (huffman-encode lzstr))
       (d   (huffman-decode (first h) (third h) (second h))))
  (lzw-decompress-to-string d))

(let* ((str "This is a test")
       (enc (ubstream:with-output-to-ubyte-stream (s)
              (write-compression str s)))
       (dec (ubstream:with-input-from-ubyte-stream (s enc)
              (read-compression s))))
  dec)

|#

;; ----------------------------------------------------------------

(defun aont-encode (x)
  ;; x is string or vector
  (encode-bytes-to-base64
   (aont-transform
    (ubstream:with-output-to-ubyte-stream (s)
      (write-compression x s))
    )))


(defun aont-decode (str)
  (ubstream:with-input-from-ubyte-stream (s (aont-untransform
                                             (decode-bytes-from-base64 str)))
    (read-compression s)))

(defun aont-decode-to-string (str)
  (map 'string 'code-char (aont-decode str)))

;; ----------------------------------------------------------------
#|
(let ((tstv (file-vector "VTuning/crypto/tools/aont.lisp")))
  (map 'string 'code-char (cvt-to-octets (lzw-compress tstv))))

(let* ((v       (file-vector "VTuning/crypto/tools/aont.lisp"))
       (etstv   (aont-transform v))
       (etstv64 (encode-bytes-to-base64 etstv))
       (dtstv64 (decode-bytes-from-base64 etstv64))
       (dtstv   (aont-untransform dtstv64)))
  (list (equalp etstv dtstv64)
        (equalp dtstv v)
        etstv64))


(let* ((v       (file-vector "VTuning/crypto/tools/aont.lisp"))
       (lzv     (lzw-compress v))
       (lzvx    (cvt-to-octets lzv))
       (lzvxx   (cvt-from-octets lzvx))
       (dv      (lzw-decompress lzvxx)))
  (list (equalp dv v)
        dv))

(let* ((v       (file-vector "VTuning/crypto/tools/aont.lisp"))
       (lzv     (lzw-compress v))
       (lzve    (cvt-to-octets lzv))
       (etstv   (aont-transform lzve))
       (etstv64 (encode-bytes-to-base64 etstv))
       (dtstv64 (decode-bytes-from-base64 etstv64))
       (dtstv   (aont-untransform dtstv64))
       (dlzv    (cvt-from-octets dtstv))
       (dv      (lzw-decompress dlzv))
       )
  (list (equalp etstv dtstv64)
        (equalp dtstv lzve)
        (equalp dlzv  lzv)
        (equalp dv    v)
        etstv64))


(let* ((tstv (file-vector "VTuning/crypto/tools/aont.lisp"))
       (raw  (encode-bytes-to-base64 (aont-transform tstv)))
       (cmp  (aont-encode tstv)))
  (list (length raw) (length cmp)))

|#