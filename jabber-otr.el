;;; jabber-otr.el --- Off-The-Record messaging for jabber.el  -*- lexical-binding: t; -*-

;; Copyright (C) 2014  Magnus Henoch

;; Author: Magnus Henoch <magnus@erlang-solutions.com>
;; Keywords: comm

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.

;;; Commentary:

;; 

;;; Code:

(require 'json)

(defvar jabber-otr-program
  (expand-file-name "emacs-otr.py" (file-name-directory load-file-name))
  "Location of the emacs-otr.py program.")

(defvar jabber-otr-dir (locate-user-emacs-file "jabber-otr"))

(defvar jabber-otr-process nil)

(defvar jabber-otr--state 'plaintext
  "State of OTR state machine for contact in current buffer.
Either plaintext, encrypted or finished.")
(make-variable-buffer-local 'jabber-otr--state)

(defvar jabber-otr--our-key-fingerprint nil
  "Fingerprint of our public key.")
(make-variable-buffer-local 'jabber-otr--our-key-fingerprint)

(defvar jabber-otr--their-key-fingerprint nil
  "Fingerprint of public key of contact in current buffer.")
(make-variable-buffer-local 'jabber-otr--their-key-fingerprint)

(defvar jabber-otr--debug nil
  "Display debug messages for OTR program.")

(defun jabber-otr-start ()
  ;; TODO: when requiring Emacs 24.5, use with-file-modes
  (let ((old-umask (default-file-modes)))
    ;; This directory should be readable only by the owner.
    (set-default-file-modes #o700)
    (unwind-protect
	(make-directory jabber-otr-dir t)
      (set-default-file-modes old-umask)))
  (let* (;; Need to use raw-text to get byte counts right
	 (coding-system-for-write 'raw-text)
	 (coding-system-for-read 'raw-text)
	 (process (start-process "jabber-otr" (generate-new-buffer "jabber-otr")
				 jabber-otr-program (expand-file-name jabber-otr-dir))))
    (setq jabber-otr-process process)
    (set-process-filter process 'jabber-otr-filter)
    (set-process-sentinel process 'jabber-otr-sentinel)))

(defun jabber-otr--ensure-started ()
  (unless (process-live-p jabber-otr-process)
    (jabber-otr-start)))

(defun jabber-otr--send-command (process json-command)
  (when jabber-otr--debug
    (message "Sending to process: %S" json-command))
  ;; Need to add trailing newline - apparently the remote process uses
  ;; line buffering.
  (let ((encoded (encode-coding-string (concat (json-encode json-command) "\n")
				       'utf-8)))
    ;; I'd like to send these in one call, but would that make my
    ;; unibyte string multibyte and confuse things?..
    (send-string process (format "%d\n" (length encoded)))
    (send-string process encoded)))

(defun jabber-otr-filter (process text)
  (with-current-buffer (process-buffer process)
    (goto-char (point-max))
    (insert text)

    (goto-char (point-min))
    (catch 'need-more-data
      (while (looking-at "\\([0-9]+\\)\n")
	(let ((nbytes (string-to-number (match-string 1))))
	  (goto-char (match-end 0))
	  (if (< (- (point-max) (point)) nbytes)
	      (throw 'need-more-data nil)
	    (let ((data (decode-coding-string
			 (delete-and-extract-region (point) (+ (point) nbytes))
			 'utf-8)))
	      (delete-region (point-min) (point))
	      (jabber-otr-handle-response process (json-read-from-string data)))))))))

(defun jabber-otr-sentinel (process reason)
  (when (= (aref reason (1- (length reason))) ?\n)
    (setq reason (substring reason 0 -1)))
  (message "jabber-otr process died!  Reason: '%s', output: '%s'"
	   reason
	   (with-current-buffer (process-buffer process)
	     (buffer-string))))

(defun jabber-otr-handle-response (_process response)
  (when jabber-otr--debug
    (message "Got response: %S" response))
  (let* ((closure (cdr (assq 'closure response)))
	 (us (aref closure 1))
	 (them (aref closure 2))
	 (buffer (get-buffer (jabber-chat-get-buffer them)))
	 (new-state (intern (cdr (assq 'new_state response))))
	 (type (and (arrayp closure) (aref closure 0)))
	 (our-fingerprint (cdr (assq 'our_fingerprint response)))
	 (their-fingerprint (cdr (assq 'their_fingerprint response))))
    (when buffer
      (with-current-buffer buffer
	(let ((previous-state jabber-otr--state)
	      (our-previous-key jabber-otr--our-key-fingerprint)
	      (their-previous-key jabber-otr--their-key-fingerprint))
	  ;; TODO: appropriate for all states?
	  (setq jabber-send-function 'jabber-otr-send)
	  (setq jabber-otr--state new-state)
	  (unless (eq previous-state new-state)
	    (ewoc-enter-last
	     jabber-chat-ewoc
	     (list :notice (format "OTR state changed from %s to %s"
				   previous-state new-state)
		   :time (current-time))))
	  (unless (equal our-previous-key our-fingerprint)
	    (setq jabber-otr--our-key-fingerprint our-fingerprint)
	    (ewoc-enter-last
	     jabber-chat-ewoc
	     (list :notice (format "Our key fingerprint is %s" our-fingerprint)
		   :time (current-time))))
	  (setq jabber-otr--their-key-fingerprint their-fingerprint)
	  ;; TODO: verify contact's fingerprint
	  (cond
	   ((null their-previous-key)
	    (ewoc-enter-last
	     jabber-chat-ewoc
	     (list :notice (format "%s's fingerprint is %s"
				   (jabber-jid-displayname jabber-chatting-with)
				   their-fingerprint)
		   :time (current-time))))
	   ((not (equal their-fingerprint their-previous-key))
	    (ewoc-enter-last
	     jabber-chat-ewoc
	     (list :notice (format "%s's fingerprint changed from %s to %s"
				   (jabber-jid-displayname jabber-chatting-with)
				   their-previous-key
				   their-fingerprint)
		   :time (current-time))))))))
    (cond
     ((equal type "send")
      (let* ((jc (jabber-find-connection us))
	     (injected-messages (cdr (assq 'injected response)))
	     (result (cdr (assq 'result response))))
	;; TODO: injected?  I'm not sure why we sometimes get one and
	;; sometimes the other.
	(dolist (injected (append injected-messages nil))
	  (jabber-send-message jc them nil injected "chat"))
	(when result
	  (jabber-send-message jc them nil result "chat"))))
     ((equal type "receive")
      (let* ((n (aref closure 3))
	     (entry (assq n jabber-otr--messages-in-flight))
	     (injected-messages (cdr (assq 'injected response)))
	     (result (cdr (assq 'result response)))
	     (err (cdr (assq 'error response)))
	     (jc (jabber-find-connection us)))
	;; TODO: handle result too
	;; Convert injected-messages from vector to list
	(dolist (injected (append injected-messages nil))
	  (jabber-send-message jc them nil injected "chat"))
	(setq jabber-otr--messages-in-flight
	      (delq entry jabber-otr--messages-in-flight))
	(let ((in-flight-notice (assq 'otr-in-flight (cdr entry))))
	  (cond
	   (result
	    (setf (car in-flight-notice) 'otr-decoded)
	    (setf (cadr in-flight-notice) result))
	   (err
	    (setf (car in-flight-notice) 'otr-error)
	    (setf (cadr in-flight-notice) err))
	   (t
	    (setf (car in-flight-notice) 'otr-nothing))))
	;; Now how do I redisplay this...
	(when buffer
	  (with-current-buffer buffer
	    ;; This _should_ almost always be the last node.
	    ;; Go backwards if needed just to be sure...
	    ;; TODO: don't go all the way if it's missing
	    ;; for some reason.
	    (let ((node (ewoc-nth jabber-chat-ewoc -1))
		  (inhibit-read-only t))
	      (while (and node
			  (or (not (eq (cadr (ewoc-data node))
				       (cdr entry)))
			      (prog1 nil
				(if (or result err)
				    (ewoc-invalidate jabber-chat-ewoc node)
				  ;; This is just "chatter" between
				  ;; the OTR implementations -
				  ;; delete.
				  (ewoc-delete jabber-chat-ewoc node)))))
		(setq node (ewoc-prev jabber-chat-ewoc node)))))))))))

;;;###autoload
(defun jabber-otr-encrypt ()
  "Request to activate encryption in the current chat buffer."
  (interactive)
  (unless (derived-mode-p 'jabber-chat-mode)
    (error "Not in chat buffer"))
  ;; Attempt to activate encryption no matter what state we (think we)
  ;; are in.
  (setq jabber-send-function 'jabber-otr-send)
  (jabber-otr--ensure-started)
  (jabber-otr--send-command
   jabber-otr-process
   (list :command "send"
	 :account (jabber-connection-bare-jid jabber-buffer-connection)
	 :contact (jabber-jid-user jabber-chatting-with)
	 :body "?OTRv?"
	 :closure (list "send" (jabber-connection-bare-jid jabber-buffer-connection)
			jabber-chatting-with))))

(defun jabber-otr-send (jc message)
  "Function for use as `jabber-send-function' in encrypted chats.
This doesn't directly send an XMPP stanza, but sends it to our
OTR driver and waits for instructions."
  (if (eq jabber-otr--state 'encrypted)
       (let ((our-jid (jabber-connection-bare-jid jc)))
	 (jabber-otr--ensure-started)
	 (jabber-maybe-print-rare-time
	  (ewoc-enter-last
	   jabber-chat-ewoc
	   (list :local `(message () (body () ,message))
		 :time (current-time))))
	 (jabber-otr--send-command
	  jabber-otr-process
	  (list :command "send"
		:account our-jid
		:contact (jabber-jid-user jabber-chatting-with)
		:body message
		:closure (list "send" our-jid jabber-chatting-with))))
    (error "Attempted to send encrypted message in OTR state %s"
	   jabber-otr--state)))

(defun jabber-otr-receive (us them message n)
  (jabber-otr--send-command
   jabber-otr-process
   (list :command "receive"
	 :account us
	 :contact them
	 :body message
	 :closure (list "receive" us them n))))

;; This needs to come before jabber-chat-normal-body:
(eval-after-load "jabber-chat"
  '(add-to-list 'jabber-body-printers 'jabber-otr--print-body))

;; This needs to come before jabber-process-chat
(eval-after-load "jabber-core"
  '(add-to-list 'jabber-message-chain 'jabber-otr--handle-message))

(defvar jabber-otr--counter 0)

(defvar jabber-otr--messages-in-flight ())

(defun jabber-otr--handle-message (jc xml-data)
  (let ((body (jabber-xml-path xml-data '(body "")))
	(them (jabber-jid-user (jabber-xml-get-attribute xml-data 'from)))
	(us (jabber-connection-bare-jid jc)))
    (when (and body (string-prefix-p "?OTR" body))
      ;; This looks like an OTR message.
      (jabber-otr--ensure-started)
      (let ((n (cl-incf jabber-otr--counter)))
	(nconc xml-data (list (list 'otr-in-flight () (number-to-string n))))
	(push (cons n xml-data) jabber-otr--messages-in-flight)
	(jabber-otr-receive us them body n)))))

(defun jabber-otr--print-body (xml-data who mode)
  (when (eq who :foreign)
    (let ((otr-in-flight (jabber-xml-path xml-data '(otr-in-flight)))
	  (otr-decoded (jabber-xml-path xml-data '(otr-decoded)))
	  (otr-error (jabber-xml-path xml-data '(otr-error)))
	  (otr-nothing (jabber-xml-path xml-data '(otr-nothing))))
      (cl-case mode
	(:printp
	 ;; Just checking whether we would output anything - "yes"
	 ;; is correct enough.
	 (or otr-in-flight otr-decoded otr-error otr-nothing))
	(:insert
	 (cond
	  (otr-decoded
	   (insert (cadr otr-decoded))
	   t)
	  (otr-in-flight
	   ;; TODO: we don't know if this will end up being an actual
	   ;; message.
	   (insert "[OTR message in flight]")
	   t)
	  (otr-error
	   (insert "[OTR error: " (cadr otr-error) "]")
	   t)
	  (otr-nothing
	   ;; This shouldn't happen, as we try to remove such entries
	   ;; from the ewoc.
	   (insert "[OTR negotiation message]")
	   t)))))))

(provide 'jabber-otr)
;;; jabber-otr.el ends here
