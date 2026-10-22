;; GNU Guix reproducible package & manifest definition for urchin
;; Build Docker image:
;;   guix pack -f docker -S /bin=bin -S /etc=etc -S /share=share -m manifest.scm

(use-modules (guix packages)
             (guix gexp)
             (guix build-system gnu)
             (guix build-system trivial)
             ((guix licenses) #:prefix license:)
             (gnu packages certs)
             (gnu packages base)
             (gnu packages bash)
             (gnu packages rust)
             (gnu packages commencement))

;; 1. Source-built package definition (compiles all 3 crates from source inside Guix sandbox)
(define-public urchin-from-source
  (package
    (name "urchin-from-source")
    (version "0.1.0")
    (source (local-file "." "urchin-checkout"
                        #:recursive? #t
                        #:select? (lambda (file stat)
                                    (not (or (string-contains file "/target")
                                             (string-contains file "/prebuilt")
                                             (string-contains file "/.git"))))))
    (build-system gnu-build-system)
    (native-inputs
     (list rust
           (list rust "cargo")
           gcc-toolchain))
    (arguments
     (list
      #:tests? #f
      #:phases
      #~(modify-phases %standard-phases
          (delete 'configure)
          (replace 'build
            (lambda _
              (setenv "HOME" "/tmp")
              (invoke "cargo" "build" "--release" "--offline")))
          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let* ((out (assoc-ref outputs "out"))
                     (bin (string-append out "/bin")))
                (mkdir-p bin)
                (for-each
                 (lambda (prog)
                   (install-file (string-append "target/release/" prog) bin))
                 '("urchin-init"
                   "urchin-provision"
                   "urchin-health"))))))))
    (home-page "https://github.com/UberMetroid/urchin")
    (synopsis "Zero-dependency Rust CrowdSec LAPI & AppSec WAF appliance for the media stack")
    (description
     "Urchin is a hardened CrowdSec LAPI & AppSec WAF Security Engine appliance for Emby, Jellyfin, Seerr, Caddy, and Unraid host syslog built with GNU Guix and 3 zero-dependency Rust binaries.")
    (license license:expat)))

;; 2. Fast packaging of the 3 statically-linked Rust binaries + static crowdsec/cscli + staging seed
(define-public urchin-suite
  (package
    (name "urchin-suite")
    (version "0.1.0")
    (source (local-file "." "urchin-static"
                        #:recursive? #t
                        #:select? (lambda (file stat)
                                    (or (string=? file ".")
                                        (string-contains file "/prebuilt")
                                        (string-contains file "/assets")))))
    (build-system trivial-build-system)
    (native-inputs (list coreutils))
    (arguments
     (list
      #:modules '((guix build utils))
      #:builder
      #~(begin
          (use-modules (guix build utils))
          (let* ((src #$source)
                 (out #$output)
                 (bin (string-append out "/bin"))
                 (etc (string-append out "/etc"))
                 (staging-dst (string-append out "/share/crowdsec/staging"))
                 (staging-src (string-append src "/prebuilt/staging")))
            (mkdir-p bin)
            (mkdir-p etc)
            (mkdir-p staging-dst)
            (for-each
             (lambda (prog)
               (let ((src-bin (string-append src "/prebuilt/" prog))
                     (dst-bin (string-append bin "/" prog)))
                 (copy-file src-bin dst-bin)
                 (chmod dst-bin #o755)))
             '("urchin-init"
               "urchin-provision"
               "urchin-health"
               "crowdsec"
               "cscli"))
            (when (file-exists? staging-src)
              (copy-recursively staging-src staging-dst))
            (call-with-output-file (string-append etc "/passwd")
              (lambda (port)
                (display "root:x:0:0:root:/root:/bin/sh\nnobody:x:99:100:Unraid Nobody:/var/lib/crowdsec:/bin/sh\n" port)))
            (call-with-output-file (string-append etc "/group")
              (lambda (port)
                (display "root:x:0:\nnobody:x:99:\nusers:x:100:nobody\n" port)))
            (call-with-output-file (string-append etc "/nsswitch.conf")
              (lambda (port)
                (display "hosts: files dns\n" port)))))))
    (home-page "https://github.com/UberMetroid/urchin")
    (synopsis "Zero-dependency static Rust CrowdSec LAPI & AppSec WAF appliance for the media stack")
    (description
     "Urchin is a hardened CrowdSec LAPI & AppSec WAF Security Engine appliance built with GNU Guix, static crowdsec/cscli binaries, and 3 zero-dependency static Rust binaries (urchin-init, urchin-provision, urchin-health).")
    (license license:expat)))

(concatenate-manifests
 (list (packages->manifest (list urchin-suite))
       (specifications->manifest
        '("nss-certs"
          "coreutils"
          "bash-minimal"))))
