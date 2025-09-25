;; sBTC Security Scanner - Alert System Contract
;; Manages security alerts and notification thresholds

;; Constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_UNAUTHORIZED (err u3000))
(define-constant ERR_INVALID_THRESHOLD (err u3001))
(define-constant ERR_ALERT_NOT_FOUND (err u3002))
(define-constant ERR_SUBSCRIPTION_FAILED (err u3003))

;; Alert levels
(define-constant ALERT_LOW u1)
(define-constant ALERT_MEDIUM u2)
(define-constant ALERT_HIGH u3)
(define-constant ALERT_CRITICAL u4)

;; Data Variables
(define-data-var alert-system-enabled bool true)
(define-data-var global-alert-threshold uint u50)
(define-data-var max-alerts-per-protocol uint u100)

;; Data Maps
(define-map alert-subscriptions
  { subscriber: principal, protocol: principal }
  {
    alert-level-threshold: uint,
    subscribed-at: uint,
    is-active: bool
  }
)

(define-map active-alerts
  { alert-id: uint }
  {
    protocol-address: principal,
    alert-level: uint,
    risk-score: uint,
    message: (string-ascii 500),
    created-at: uint,
    is-resolved: bool,
    resolver: (optional principal)
  }
)

(define-map protocol-alert-count
  { protocol-address: principal }
  { count: uint, last-alert: uint }
)

(define-map alert-counter
  { counter: (string-ascii 10) }
  { value: uint }
)

;; Initialize alert counter
(map-set alert-counter { counter: "global" } { value: u0 })

;; Private Functions

;; Get next alert ID
(define-private (get-next-alert-id)
  (let (
    (current-id (default-to u0 (get value (map-get? alert-counter { counter: "global" }))))
    (next-id (+ current-id u1))
  )
    (map-set alert-counter { counter: "global" } { value: next-id })
    next-id
  )
)

;; Determine alert level based on risk score
(define-private (calculate-alert-level (risk-score uint))
  (if (<= risk-score u25)
    ALERT_LOW
    (if (<= risk-score u50)
      ALERT_MEDIUM
      (if (<= risk-score u75)
        ALERT_HIGH
        ALERT_CRITICAL
      )
    )
  )
)

;; Check if protocol has too many alerts
(define-private (check-alert-limit (protocol-address principal))
  (let (
    (current-count (default-to u0 (get count (map-get? protocol-alert-count { protocol-address: protocol-address }))))
  )
    (< current-count (var-get max-alerts-per-protocol))
  )
)

;; Public Functions

;; Create security alert
(define-public (create-alert 
    (protocol-address principal) 
    (risk-score uint) 
    (message (string-ascii 500)))
  (let (
    (alert-id (get-next-alert-id))
    (alert-level (calculate-alert-level risk-score))
    (current-count (default-to u0 (get count (map-get? protocol-alert-count { protocol-address: protocol-address }))))
  )
    (asserts! (var-get alert-system-enabled) ERR_SUBSCRIPTION_FAILED)
    (asserts! (>= risk-score (var-get global-alert-threshold)) ERR_INVALID_THRESHOLD)
    (asserts! (check-alert-limit protocol-address) ERR_SUBSCRIPTION_FAILED)
    
    ;; Create alert
    (map-set active-alerts
      { alert-id: alert-id }
      {
        protocol-address: protocol-address,
        alert-level: alert-level,
        risk-score: risk-score,
        message: message,
        created-at: stacks-block-height,
        is-resolved: false,
        resolver: none
      }
    )
    
    ;; Update protocol alert count
    (map-set protocol-alert-count
      { protocol-address: protocol-address }
      { count: (+ current-count u1), last-alert: stacks-block-height }
    )
    
    (ok { alert-id: alert-id, alert-level: alert-level })
  )
)

;; Subscribe to protocol alerts
(define-public (subscribe-to-alerts 
    (protocol principal) 
    (threshold uint))
  (begin
    (asserts! (var-get alert-system-enabled) ERR_SUBSCRIPTION_FAILED)
    (asserts! (and (>= threshold u1) (<= threshold u100)) ERR_INVALID_THRESHOLD)
    
    (ok (map-set alert-subscriptions
      { subscriber: tx-sender, protocol: protocol }
      {
        alert-level-threshold: threshold,
        subscribed-at: stacks-block-height,
        is-active: true
      }
    ))
  )
)

;; Unsubscribe from protocol alerts
(define-public (unsubscribe-from-alerts (protocol principal))
  (let (
    (subscription (unwrap! 
      (map-get? alert-subscriptions { subscriber: tx-sender, protocol: protocol })
      ERR_ALERT_NOT_FOUND
    ))
  )
    (ok (map-set alert-subscriptions
      { subscriber: tx-sender, protocol: protocol }
      (merge subscription { is-active: false })
    ))
  )
)

;; Resolve alert (mark as handled)
(define-public (resolve-alert (alert-id uint))
  (let (
    (alert-data (unwrap! 
      (map-get? active-alerts { alert-id: alert-id })
      ERR_ALERT_NOT_FOUND
    ))
  )
    (asserts! (not (get is-resolved alert-data)) ERR_ALERT_NOT_FOUND)
    
    (ok (map-set active-alerts
      { alert-id: alert-id }
      (merge alert-data { 
        is-resolved: true, 
        resolver: (some tx-sender) 
      })
    ))
  )
)

;; Bulk create alerts (for scanner integration)
(define-public (create-bulk-alerts 
    (protocol-address principal)
    (alerts (list 10 { risk-score: uint, message: (string-ascii 500) })))
  (let (
    (results (map create-single-alert alerts))
  )
    (asserts! (var-get alert-system-enabled) ERR_SUBSCRIPTION_FAILED)
    (ok results)
  )
)

;; Helper for bulk alert creation
(define-private (create-single-alert (alert-data { risk-score: uint, message: (string-ascii 500) }))
  (let (
    (risk-score (get risk-score alert-data))
    (message (get message alert-data))
  )
    (if (>= risk-score (var-get global-alert-threshold))
      (get-next-alert-id)  ;; Simplified - would call create-alert
      u0
    )
  )
)

;; Read-only Functions

;; Get alert details
(define-read-only (get-alert (alert-id uint))
  (map-get? active-alerts { alert-id: alert-id })
)

;; Get subscription details
(define-read-only (get-subscription (subscriber principal) (protocol principal))
  (map-get? alert-subscriptions { subscriber: subscriber, protocol: protocol })
)

;; Get protocol alert statistics
(define-read-only (get-protocol-alert-stats (protocol-address principal))
  (map-get? protocol-alert-count { protocol-address: protocol-address })
)

;; Check if subscriber should receive alert
(define-read-only (should-notify-subscriber 
    (subscriber principal) 
    (protocol principal) 
    (risk-score uint))
  (let (
    (subscription (map-get? alert-subscriptions { subscriber: subscriber, protocol: protocol }))
  )
    (match subscription
      some-sub (and 
        (get is-active some-sub)
        (>= risk-score (get alert-level-threshold some-sub))
      )
      false
    )
  )
)

;; Get alert system configuration
(define-read-only (get-alert-config)
  {
    enabled: (var-get alert-system-enabled),
    global-threshold: (var-get global-alert-threshold),
    max-alerts: (var-get max-alerts-per-protocol)
  }
)

;; Admin Functions

;; Update alert system configuration
(define-public (update-alert-config 
    (enabled bool) 
    (threshold uint) 
    (max-alerts uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    (asserts! (and (>= threshold u1) (<= threshold u100)) ERR_INVALID_THRESHOLD)
    
    (var-set alert-system-enabled enabled)
    (var-set global-alert-threshold threshold)
    (var-set max-alerts-per-protocol max-alerts)
    (ok true)
  )
)

;; Clear resolved alerts (cleanup)
(define-public (cleanup-resolved-alerts (alert-ids (list 20 uint)))
  (begin
    (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_UNAUTHORIZED)
    ;; In full implementation, would remove resolved alerts
    (ok (len alert-ids))
  )
)

