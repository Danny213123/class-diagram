# ArtX Platform - Simple Class Diagram Overview

A simplified class structure covering all activity and sequence diagram flows.

```mermaid
classDiagram
    %% ============================================================
    %% USERS
    %% ============================================================
    class User {
        +String userId
        +String email
        +String userType
    }

    class Artist {
        +String artistId
        +Portfolio portfolio
    }

    class Buyer {
        +String buyerId
        +ShoppingCart cart
    }

    class CustomerSupport {
        +String csrId
    }

    class Admin {
        +String adminId
    }

    %% ============================================================
    %% CORE ENTITIES
    %% ============================================================
    class Artwork {
        +String artworkId
        +String title
        +Double price
        +String status
    }

    class Portfolio {
        +String portfolioId
        +String bio
        +List~Artwork~ artworks
    }

    class Transaction {
        +String transactionId
        +Double amount
        +String status
    }

    class Auction {
        +String auctionId
        +Double currentBid
        +List~Bid~ bids
    }

    class Bid {
        +String bidId
        +Double amount
    }

    class SupportTicket {
        +String ticketId
        +String subject
        +String status
    }

    class ShoppingCart {
        +String cartId
        +List~Artwork~ items
    }

    %% ============================================================
    %% SYSTEM COMPONENTS
    %% ============================================================
    class System {
        +validateInput()
        +processRequest()
        +handleError()
    }

    class Database {
        +store()
        +retrieve()
        +update()
    }

    class PaymentGateway {
        +processPayment()
        +refund()
    }

    class EmailService {
        +sendEmail()
    }

    %% ============================================================
    %% RELATIONSHIPS
    %% ============================================================

    %% User Inheritance
    User <|-- Artist
    User <|-- Buyer
    User <|-- CustomerSupport
    User <|-- Admin

    %% User Ownership
    Artist --> Portfolio : owns
    Artist --> Artwork : creates
    Buyer --> ShoppingCart : has
    Buyer --> Transaction : makes
    User --> SupportTicket : submits

    %% Entity Relationships
    Portfolio --> Artwork : contains
    Auction --> Artwork : for
    Auction --> Bid : contains
    Transaction --> Artwork : references

    %% System Interactions
    User --> System : interacts
    System --> Database : stores/retrieves
    System --> PaymentGateway : processes payments
    System --> EmailService : sends emails

    %% Data Persistence
    Artwork --> Database : stored in
    Portfolio --> Database : stored in
    Transaction --> Database : stored in
    Auction --> Database : stored in
    SupportTicket --> Database : stored in
```

## Covered Activity Flows

This simple diagram supports all the following activity/sequence flows:

### User Management
- **Registration**: User → System → Database + EmailService
- **Login**: User → System → Database
- **Authentication**: System validates credentials from Database

### Artist Activities
- **Portfolio Creation**: Artist → System → Database (Admin approval)
- **Artwork Upload**: Artist → Artwork → System → Database
- **Artwork Listing**: Artist → Artwork → System → Database (Admin review)

### Buyer Activities
- **Marketplace Browsing**: Buyer → System → Database (retrieve artworks)
- **Purchase**: Buyer → Transaction → System → PaymentGateway → Database
- **Auction Participation**: Buyer → Bid → Auction → System → Database

### Financial Operations
- **Fund Transfer**: User → System → PaymentGateway → Database
- **Transaction History**: User → System → Database

### Support System
- **Ticket Submission**: User → SupportTicket → System → Database + EmailService
- **Ticket Management**: CustomerSupport → SupportTicket → System → Database

### Admin Functions
- **Application Review**: Admin → System → Database
- **Content Moderation**: Admin → System → Database
