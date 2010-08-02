;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;; See the LICENSE file for licensing information.

(in-package #:cl-user)

(defpackage #:cl-sha1-asd
  (:use :cl :asdf))


(in-package #:cl-sha1-asd)


(defvar *sha1-version* "0.0.1"
  "A string denoting the current version of cl-sha1.")

(export '*sha1-version*)


(defsystem #:cl-sha1
  :name "CL-SHA1"
  :version #.*sha1-version*
  :maintainer "M.L. Oppermann <M.L.Oppermann@gmail.com>"
  :author "M.L. Oppermann <M.L.Oppermann@gmail.com>"
  :licence "To be determined"
  :description ""
  :long-description "CL-SHA1 is a binary client to sha1"
  :serial t
  :components ((:file "package")
               (:file "cl-sha1"))
  :depends-on ())
