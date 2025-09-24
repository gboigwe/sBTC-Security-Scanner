;; sBTC Security Scanner - Risk Oracle Contract
;; Provides risk assessment functionality for DeFi protocols

;; Constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u1000))
(define-constant ERR_INVALID_RISK_LEVEL (err u1001))
(define-constant ERR_PROTOCOL_NOT_FOUND (err u1002))

;; Data Variables
(define-data-var oracle-enabled bool true)
(define-data-var min-risk-threshold uint u1)
(define-data-var max-risk-threshold uint u100)

;; Data Maps
(define-map protocol-risk-scores 
  { protocol-address: principal } 
  { 
    risk-score: uint,
    last-updated: uint,
    assessment-count: uint
  }
)

(define-map authorized-assessors 
  { assessor: principal } 
  { authorized: bool, added-at: uint }
)

;; Public Functions

;; Initialize risk assessment for a protocol
(define-public (initialize-protocol (protocol-address principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (ok (map-set protocol-risk-scores
      { protocol-address: protocol-address }
      { 
        risk-score: u50, ;; Default medium risk
        last-updated: stacks-block-height,
        assessment-count: u0
      }
    ))
  )
)

;; Update risk score for a protocol
(define-public (update-risk-score (protocol-address principal) (new-score uint))
  (let (
    (current-data (unwrap! (map-get? protocol-risk-scores { protocol-address: protocol-address }) ERR_PROTOCOL_NOT_FOUND))
    (is-authorized (default-to false (get authorized (map-get? authorized-assessors { assessor: tx-sender }))))
  )
    (asserts! (or (is-eq tx-sender CONTRACT_OWNER) is-authorized) ERR_UNAUTHORIZED)
    (asserts! (and (>= new-score (var-get min-risk-threshold)) (<= new-score (var-get max-risk-threshold))) ERR_INVALID_RISK_LEVEL)
    
    (ok (map-set protocol-risk-scores
      { protocol-address: protocol-address }
      { 
        risk-score: new-score,
        last-updated: stacks-block-height,
        assessment-count: (+ (get assessment-count current-data) u1)
      }
    ))
  )
)

;; Add authorized assessor
(define-public (authorize-assessor (assessor principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (ok (map-set authorized-assessors
      { assessor: assessor }
      { authorized: true, added-at: stacks-block-height }
    ))
  )
)

;; Read-only functions

;; Get protocol risk score
(define-read-only (get-protocol-risk (protocol-address principal))
  (map-get? protocol-risk-scores { protocol-address: protocol-address })
)

;; Check if assessor is authorized
(define-read-only (is-authorized-assessor (assessor principal))
  (default-to false (get authorized (map-get? authorized-assessors { assessor: assessor })))
)

;; Get current risk thresholds
(define-read-only (get-risk-thresholds)
  { 
    min: (var-get min-risk-threshold),
    max: (var-get max-risk-threshold),
    oracle-enabled: (var-get oracle-enabled)
  }
)

;; Calculate risk category based on score
(define-read-only (get-risk-category (risk-score uint))
  (if (<= risk-score u25)
    "low"
    (if (<= risk-score u50)
      "medium-low"
      (if (<= risk-score u75)
        "medium-high"
        "high"
      )
    )
  )
)

;; Admin functions

;; Update risk thresholds
(define-public (update-risk-thresholds (min-threshold uint) (max-threshold uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (< min-threshold max-threshold) ERR_INVALID_RISK_LEVEL)
    (var-set min-risk-threshold min-threshold)
    (var-set max-risk-threshold max-threshold)
    (ok true)
  )
)

;; Toggle oracle status
(define-public (toggle-oracle (enabled bool))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (var-set oracle-enabled enabled)
    (ok enabled)
  )
)
