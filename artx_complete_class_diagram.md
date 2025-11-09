# ArtX Platform - Complete Unified Class Diagram

This comprehensive class diagram integrates all components of the ArtX platform, organized by architectural layers.

```mermaid
classDiagram
    %% ============================================================
    %% PRESENTATION LAYER - User Interface & Dashboards
    %% ============================================================
    class UserInterface {
        -String sessionId
        -String currentPage
        -FormData formData
        +displayRegistrationForm()
        +displayLoginForm()
        +displayDashboard()
        +displayErrorMessage(message)
        +collectFormData()
        +submitForm(data)
        +navigateToPage(page)
    }

    class ArtistDashboard {
        -String artistId
        -Portfolio portfolio
        -List~Artwork~ artworks
        +createPortfolio(portfolioData)
        +uploadArtwork(artworkData)
        +listArtworkForSale(artworkId, price)
        +manageCommissions()
        +viewSalesHistory()
        +withdrawFunds()
    }

    class BuyerDashboard {
        -String buyerId
        -ShoppingCart cart
        -List~Order~ orders
        +browseMarketplace(filters)
        +purchaseArtwork(artworkId)
        +requestCommission(artistId, details)
        +participateInAuction(auctionId)
        +viewTransactionHistory()
    }

    class CSRDashboard {
        -String supportId
        -List~SupportTicket~ assignedTickets
        +viewSupportTickets()
        +assignTicket(ticketId)
        +respondToTicket(ticketId, response)
        +escalateTicket(ticketId)
        +accessClientInfo(userId)
    }

    class AdminDashboard {
        -String adminId
        -List~Permission~ permissions
        +reviewArtistApplications()
        +approveApplication(applicationId)
        +moderateContent(contentId)
        +manageUserAccounts(userId)
        +viewSystemMetrics()
    }

    %% ============================================================
    %% USER & AUTHENTICATION LAYER
    %% ============================================================
    class User {
        <<abstract>>
        -String userId
        -String email
        -String username
        -String passwordHash
        -UserType userType
        -AccountStatus status
        -Date registrationDate
        -Boolean isVerified
        +register()
        +login()
        +logout()
        +updateProfile()
        +verifyEmail()
    }

    class Artist {
        -String artistId
        -String bio
        -Portfolio portfolio
        -Double commissionRate
        -Boolean isApproved
        +createPortfolio()
        +uploadArtwork()
        +setCommissionRate()
        +acceptCommission()
    }

    class Buyer {
        -String buyerId
        -Address shippingAddress
        -ShoppingCart cart
        -List~String~ watchlist
        +browseMarketplace()
        +purchaseArtwork()
        +requestCommission()
        +placeBid()
    }

    class CustomerSupportRep {
        -String csrId
        -String department
        -Integer activeTickets
        +viewTickets()
        +respondToTicket()
        +escalateTicket()
        +accessClientInfo()
    }

    class Admin {
        -String adminId
        -AdminLevel level
        -List~Permission~ permissions
        +reviewApplications()
        +moderateContent()
        +manageAccounts()
        +handleEscalations()
    }

    class UserType {
        <<enumeration>>
        ARTIST
        BUYER
        CUSTOMER_SUPPORT
        ADMIN
    }

    class AccountStatus {
        <<enumeration>>
        PENDING_VERIFICATION
        ACTIVE
        SUSPENDED
        BANNED
    }

    class AdminLevel {
        <<enumeration>>
        JUNIOR_ADMIN
        SENIOR_ADMIN
        SUPER_ADMIN
    }

    %% ============================================================
    %% CONTROLLER LAYER
    %% ============================================================
    class AuthenticationController {
        -AuthenticationService authService
        -ValidationService validator
        +registerUser(userData)
        +loginUser(credentials)
        +logoutUser(sessionId)
        +validateInputFormat(data)
        +generateVerificationToken()
        +verifyEmailToken(token)
    }

    class MarketplaceController {
        -SearchEngine searchEngine
        -FilterManager filterManager
        +browseArtworks(filters)
        +searchArtworks(query)
        +applyFilters(criteria)
        +getArtworkDetails(artworkId)
        +getFeaturedArtworks()
    }

    class PortfolioController {
        -String portfolioId
        -ValidationService validator
        +createPortfolio(portfolioData)
        +updatePortfolio(updates)
        +uploadArtwork(artworkData)
        +removeArtwork(artworkId)
        +setPortfolioVisibility(visibility)
    }

    class ArtworkController {
        -FileUploadService fileService
        -ImageProcessor imageProcessor
        +uploadArtwork(file, metadata)
        +validateArtworkFile(file)
        +processImage(image)
        +generateThumbnail(image)
        +listForSale(artworkId, price)
    }

    class TransactionController {
        -PaymentGateway paymentGateway
        -InventoryManager inventory
        +initiatePurchase(artworkId, buyerId)
        +processPayment(paymentData)
        +verifyFunds(buyerId, amount)
        +generateReceipt(transactionId)
        +processRefund(transactionId)
    }

    class CommissionController {
        -NotificationService notifier
        -MessageService messenger
        +submitCommissionRequest(request)
        +notifyArtist(artistId, request)
        +acceptCommission(commissionId)
        +rejectCommission(commissionId, reason)
        +negotiateTerms(commissionId, terms)
    }

    class AuctionController {
        -BidManager bidManager
        -TimerService timer
        +createAuction(artworkId, settings)
        +placeBid(auctionId, bidAmount)
        +validateBid(bid)
        +updateHighestBid(auctionId, bid)
        +endAuction(auctionId)
    }

    class SupportTicketController {
        -TicketQueue queue
        -TicketRouter router
        +submitTicket(ticketData)
        +validateTicketData(data)
        +generateTicketId()
        +routeTicket(ticket)
        +updateTicketStatus(ticketId, status)
    }

    class CSRController {
        -AssignmentManager assignmentManager
        -AccessControlManager accessControl
        +assignTicketToCSR(ticketId, csrId)
        +getAssignedTickets(csrId)
        +accessClientInformation(clientId)
        +escalateToAdmin(ticketId)
    }

    class AdminController {
        -EscalationHandler escalationHandler
        -TicketAnalytics analytics
        +handleEscalation(ticketId)
        +reviewCSRPerformance(csrId)
        +generateSupportMetrics()
        +manageCSRPermissions(csrId, permissions)
    }

    %% ============================================================
    %% SERVICE LAYER
    %% ============================================================
    class AuthenticationService {
        -TokenManager tokenManager
        -PasswordEncoder encoder
        -SessionManager sessionManager
        +authenticateUser(credentials)
        +generateToken(user)
        +validateToken(token)
        +checkPasswordStrength(password)
    }

    class ValidationService {
        -ValidationRules rules
        -RegexPatterns patterns
        +validateEmail(email)
        +validatePassword(password)
        +validateArtworkData(data)
        +sanitizeInput(input)
        +validateFileFormat(file)
    }

    class EncryptionService {
        -String algorithm
        -KeyManager keyManager
        +encryptPassword(password)
        +encryptUserData(data)
        +decryptData(encryptedData)
        +generateSalt()
        +hashWithSalt(data, salt)
    }

    class EmailService {
        -SMTPConfig config
        -EmailTemplates templates
        +sendVerificationEmail(email, token)
        +sendConfirmationEmail(email, message)
        +sendPasswordResetEmail(email, token)
        +sendTransactionReceipt(email, transaction)
        +queueEmail(emailData)
    }

    class NotificationService {
        -NotificationQueue queue
        -TemplateManager templates
        +sendNotification(userId, message)
        +queueNotification(notification)
        +createNotificationFromTemplate(template, data)
        +getUserNotifications(userId)
    }

    class FileUploadService {
        -StorageManager storage
        -FileValidator validator
        -VirusScannerInterface scanner
        +uploadFile(file)
        +validateFileType(file)
        +scanForVirus(file)
        +storeFile(file)
        +deleteFile(fileId)
    }

    class ImageProcessor {
        -ImageManipulator manipulator
        -CompressionEngine compressor
        +resizeImage(image, dimensions)
        +compressImage(image, quality)
        +generateThumbnail(image)
        +addWatermark(image, watermark)
    }

    class SearchEngine {
        -IndexManager indexManager
        -QueryParser parser
        +searchArtworks(query)
        +indexArtwork(artwork)
        +updateIndex(artworkId)
        +scoreResults(results)
    }

    class PaymentService {
        -PaymentGateway gateway
        -FraudDetector fraudDetector
        +processPayment(payment)
        +authorizePayment(amount, card)
        +refundPayment(transactionId)
        +checkFraud(transaction)
    }

    class AuditService {
        -LogWriter logWriter
        -EventTracker tracker
        +logUserAction(userId, action)
        +logTransaction(transaction)
        +logSecurityEvent(event)
        +generateAuditReport(criteria)
    }

    class SessionService {
        -SessionStore store
        -SessionValidator validator
        +createSession(userId)
        +getSession(sessionId)
        +destroySession(sessionId)
        +validateSession(sessionId)
    }

    class SecurityService {
        -FirewallManager firewall
        -RateLimiter limiter
        +checkAuthentication(request)
        +checkAuthorization(user, resource)
        +rateLimit(userId, action)
        +enforceSecurityPolicies()
    }

    class CacheService {
        -CacheStore store
        -CachePolicy policy
        +get(key)
        +set(key, value, ttl)
        +delete(key)
        +flush()
    }

    %% ============================================================
    %% DATA LAYER - Domain Models
    %% ============================================================
    class Artwork {
        -String artworkId
        -String artistId
        -String title
        -String description
        -Double price
        -String category
        -Dimensions dimensions
        -ArtworkStatus status
        -Date uploadDate
        +upload()
        +listForSale()
        +unlist()
    }

    class Portfolio {
        -String portfolioId
        -String artistId
        -String bio
        -List~Artwork~ artworks
        -Boolean isPublic
        +create()
        +addArtwork()
        +publish()
    }

    class Transaction {
        -String transactionId
        -String buyerId
        -String sellerId
        -String artworkId
        -Double amount
        -TransactionStatus status
        -Date transactionDate
        +initiate()
        +process()
        +complete()
        +refund()
    }

    class Commission {
        -String commissionId
        -String artistId
        -String buyerId
        -String description
        -Double budget
        -CommissionStatus status
        +request()
        +accept()
        +reject()
        +complete()
    }

    class Auction {
        -String auctionId
        -String artworkId
        -Double startingPrice
        -Double currentBid
        -Date endTime
        -List~Bid~ bids
        -AuctionStatus status
        +create()
        +placeBid()
        +end()
    }

    class Bid {
        -String bidId
        -String auctionId
        -String bidderId
        -Double amount
        -Date timestamp
        +place()
        +validate()
    }

    class SupportTicket {
        -String ticketId
        -String userId
        -String subject
        -String description
        -TicketStatus status
        -String assignedCSR
        +create()
        +assign()
        +escalate()
        +close()
    }

    class Order {
        -String orderId
        -String buyerId
        -List~OrderItem~ items
        -Double total
        -OrderStatus status
        +create()
        +process()
        +complete()
    }

    class ShoppingCart {
        -String cartId
        -String userId
        -List~CartItem~ items
        -Double total
        +addItem()
        +removeItem()
        +checkout()
    }

    class Message {
        -String messageId
        -String senderId
        -String recipientId
        -String content
        -Date timestamp
        +send()
        +markAsRead()
    }

    class Notification {
        -String notificationId
        -String userId
        -String message
        -NotificationType type
        -Boolean isRead
        +create()
        +send()
    }

    %% Value Objects
    class Address {
        -String street
        -String city
        -String state
        -String postalCode
        +validate()
    }

    class Dimensions {
        -Double height
        -Double width
        -String unit
        +validate()
    }

    class PaymentMethod {
        -String methodId
        -PaymentType type
        -String accountDetails
        +validate()
    }

    %% ============================================================
    %% DATA ACCESS LAYER
    %% ============================================================
    class Database {
        -ConnectionPool connectionPool
        -TransactionManager transactionManager
        +storeUserAccount(userData)
        +retrieveUserData(userId)
        +storeArtwork(artworkData)
        +storeTransaction(transactionData)
        +executeQuery(query)
        +beginTransaction()
        +commitTransaction()
    }

    class PaymentGateway {
        -PaymentProcessor processor
        -SecurityValidator validator
        +authorizePayment(paymentData)
        +capturePayment(authorizationId)
        +refundPayment(transactionId, amount)
        +getPaymentStatus(transactionId)
    }

    %% ============================================================
    %% SYSTEM INTEGRATION & FLOW
    %% ============================================================
    class ArtXSystem {
        -SystemConfiguration config
        -ServiceRegistry services
        +initialize()
        +start()
        +handleRequest(request)
        +routeToController(request)
    }

    class FlowController {
        <<abstract>>
        -FlowState currentState
        +initiateFlow()
        +validateStep()
        +transitionState()
        +handleError()
    }

    class EventSystem {
        -EventPublisher publisher
        -EventSubscriber subscriber
        +publishEvent(event)
        +subscribeToEvent(eventType, handler)
    }

    class MonitoringSystem {
        -PerformanceMonitor performance
        -ErrorTracker errors
        +trackPerformance(metric)
        +logError(error)
    }

    %% ============================================================
    %% STATUS ENUMERATIONS
    %% ============================================================
    class ArtworkStatus {
        <<enumeration>>
        DRAFT
        PUBLISHED
        FOR_SALE
        SOLD
    }

    class TransactionStatus {
        <<enumeration>>
        PENDING
        PROCESSING
        COMPLETED
        REFUNDED
    }

    class CommissionStatus {
        <<enumeration>>
        REQUESTED
        ACCEPTED
        IN_PROGRESS
        COMPLETED
    }

    class AuctionStatus {
        <<enumeration>>
        SCHEDULED
        ACTIVE
        ENDED
    }

    class TicketStatus {
        <<enumeration>>
        OPEN
        ASSIGNED
        IN_PROGRESS
        RESOLVED
    }

    class OrderStatus {
        <<enumeration>>
        PENDING
        CONFIRMED
        SHIPPED
        DELIVERED
    }

    %% ============================================================
    %% LAYER RELATIONSHIPS - Top to Bottom Flow
    %% ============================================================

    %% System Entry Point
    ArtXSystem --> UserInterface : presents
    ArtXSystem --> SecurityService : secured by
    ArtXSystem --> MonitoringSystem : monitored by
    ArtXSystem --> EventSystem : events managed by

    %% User Interface to Controllers
    UserInterface --> AuthenticationController : authentication requests
    UserInterface --> MarketplaceController : marketplace requests
    UserInterface --> SupportTicketController : support requests

    %% Dashboards
    ArtistDashboard --> PortfolioController : manages portfolio
    ArtistDashboard --> ArtworkController : manages artwork
    BuyerDashboard --> MarketplaceController : browses marketplace
    BuyerDashboard --> TransactionController : purchases
    CSRDashboard --> CSRController : manages tickets
    AdminDashboard --> AdminController : admin functions

    %% User Inheritance
    User <|-- Artist : inherits
    User <|-- Buyer : inherits
    User <|-- CustomerSupportRep : inherits
    User <|-- Admin : inherits
    User --> UserType : has type
    User --> AccountStatus : has status
    Admin --> AdminLevel : has level

    %% Controllers to Services
    AuthenticationController --> ValidationService : validates
    AuthenticationController --> EncryptionService : encrypts
    AuthenticationController --> EmailService : sends emails
    AuthenticationController --> AuthenticationService : authenticates
    AuthenticationController --> AuditService : logs events

    MarketplaceController --> SearchEngine : searches
    MarketplaceController --> ValidationService : validates

    PortfolioController --> ArtworkController : manages artwork
    PortfolioController --> FileUploadService : uploads files
    PortfolioController --> ValidationService : validates

    ArtworkController --> FileUploadService : uploads
    ArtworkController --> ImageProcessor : processes images
    ArtworkController --> ValidationService : validates

    TransactionController --> PaymentService : processes payments
    TransactionController --> ValidationService : validates
    TransactionController --> AuditService : logs

    CommissionController --> NotificationService : notifies
    CommissionController --> ValidationService : validates

    AuctionController --> NotificationService : notifies
    AuctionController --> TransactionController : finalizes sale

    SupportTicketController --> NotificationService : notifies
    SupportTicketController --> ValidationService : validates

    CSRController --> SupportTicketController : manages tickets
    AdminController --> CSRController : oversees

    %% Services to Data Layer
    AuthenticationService --> SessionService : manages sessions
    AuthenticationService --> Database : persists data

    SearchEngine --> Database : queries data
    PaymentService --> PaymentGateway : processes payments
    PaymentService --> Database : records transactions

    FileUploadService --> Database : stores metadata
    NotificationService --> Database : persists notifications
    AuditService --> Database : stores logs

    %% Data Model Relationships
    Artwork --> ArtworkStatus : has status
    Artwork --> Dimensions : has dimensions
    Portfolio --> Artwork : contains
    Transaction --> TransactionStatus : has status
    Transaction --> Artwork : references
    Transaction --> PaymentMethod : uses
    Commission --> CommissionStatus : has status
    Commission --> Message : contains
    Auction --> AuctionStatus : has status
    Auction --> Artwork : for
    Auction --> Bid : contains
    SupportTicket --> TicketStatus : has status
    SupportTicket --> Message : contains
    Order --> OrderStatus : has status
    ShoppingCart --> Artwork : references
    Buyer --> ShoppingCart : has
    Buyer --> Address : has
    Notification --> User : sent to

    %% All models persist to Database
    User --> Database : persisted in
    Artwork --> Database : persisted in
    Portfolio --> Database : persisted in
    Transaction --> Database : persisted in
    Commission --> Database : persisted in
    Auction --> Database : persisted in
    SupportTicket --> Database : persisted in
    Order --> Database : persisted in

    %% Cross-cutting Concerns
    SecurityService --> AuthenticationService : validates
    CacheService --> Database : caches from
    EventSystem --> NotificationService : triggers
```

## Architecture Overview

This unified class diagram represents the complete ArtX platform architecture organized into the following layers:

### 1. **Presentation Layer**
- UserInterface (main entry point for users)
- Role-specific dashboards (Artist, Buyer, CSR, Admin)

### 2. **User & Authentication Layer**
- User hierarchy (Artist, Buyer, CustomerSupportRep, Admin)
- User types and status enumerations

### 3. **Controller Layer**
- Authentication, Marketplace, Portfolio, Artwork
- Transaction, Commission, Auction
- Support Ticket, CSR, Admin controllers

### 4. **Service Layer**
- Core services: Authentication, Validation, Encryption
- Communication: Email, Notification
- Business logic: Search, Payment, Audit
- Infrastructure: Session, Security, Cache

### 5. **Data Layer**
- Domain models: Artwork, Portfolio, Transaction, Commission, Auction
- Support models: SupportTicket, Order, ShoppingCart
- Value objects: Address, Dimensions, PaymentMethod
- Status enumerations for all entities

### 6. **Data Access Layer**
- Database service
- Payment Gateway integration

### 7. **System Integration**
- ArtXSystem (main orchestrator)
- EventSystem (event-driven architecture)
- MonitoringSystem (observability)
- FlowController (process orchestration)

## Key Design Patterns

- **Layered Architecture**: Clear separation between presentation, business logic, and data access
- **Service-Oriented**: Reusable services across controllers
- **Repository Pattern**: Database abstraction
- **Observer Pattern**: Event system for notifications
- **State Pattern**: Flow controllers for business processes
- **Strategy Pattern**: Multiple payment methods and notification channels
