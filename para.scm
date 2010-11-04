;; first aproach to encoding datatypes as paramorphism ;;

;; need some curring macros

; paramorphism as interpretation of terms
; nats always go first ;]
(define-curry paraNat
  (lambda (s z n)
    n s z
))

; constructors - zero
(define-curry zero
  (lambda (s z)
    z
))

; succesor
(define-curry succ
  (lambda (n s z)
    s n (paraNat s z n)
))

; destructor
(define-curry pred
  (paraNat (lambda-curried (x y) y) zero)
)

; injection into church encoding
; having primitive recursion we can get primitive interation
(define-curry
  (lambda (s z n)
    (paraNat (lambda-curried (x y) (s y)) z n)
))






