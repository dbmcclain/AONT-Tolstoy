(in-package #:user)

(asdf:defsystem "aont"
  :description "aont: all or nothing encode / decode"
  :version     "1.0"
  :author      "D.McClain <dbm@refined-audiometrics.com>"
  :license     "Copyright (c) 2015 by Refined Audiometrics Laboratory, LLC. All rights reserved."
  :components  ((:file "lzw")
                (:file "aont")
                (:file "mimic")
                (:file "aont-messaging"))
  :serial       t
  :depends-on   ("core-crypto"
                 "ecc-keying"
                 ))

