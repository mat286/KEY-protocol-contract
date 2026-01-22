// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract IdentityRegistry is Ownable, Pausable, ReentrancyGuard {
    using ECDSA for bytes32;

    /*//////////////////////////////////////////////////////////////
                                CONFIG
    //////////////////////////////////////////////////////////////*/

    /// @notice Dirección pública del TEE autorizado
    address public trustedTEE;

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    struct IdentityCertificate {
        bytes32 identityCommitment;
        bytes32 biometricCommitment;
        string cid; 
        string encryptedAESKey;
        uint256 issuedAt;
        bool revoked;
    }

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    mapping(uint256 => IdentityCertificate) public identities;
    mapping(bytes32 => bool) public usedAuthorizations;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event IdentityIssued(
        uint256 indexed certId,
        bytes32 indexed identityCommitment,
        uint256 issuedAt
    );

    event IdentityRevoked(uint256 indexed certId, uint256 revokedAt);
    event TrustedTEEUpdated(address indexed oldTEE, address indexed newTEE);

    /*//////////////////////////////////////////////////////////////
                                CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        address _trustedTEE,
        address _initialOwner
    ) Ownable(_initialOwner) {
        require(_trustedTEE != address(0), "Invalid TEE address");
        trustedTEE = _trustedTEE;
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function setTrustedTEE(address _newTEE) external onlyOwner {
        require(_newTEE != address(0), "Invalid TEE address");
        address old = trustedTEE;
        trustedTEE = _newTEE;
        emit TrustedTEEUpdated(old, _newTEE);
    }

    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }

    /*//////////////////////////////////////////////////////////////
                        CORE: ISSUE IDENTITY
    //////////////////////////////////////////////////////////////*/

    function issueIdentity(
        uint256 certId,
        bytes32 identityCommitment,
        bytes32 biometricCommitment,
        string calldata cid,
        string calldata encryptedAESKey,
        uint256 timestamp,
        bytes calldata signature
    ) external whenNotPaused nonReentrant {
        require(identities[certId].issuedAt == 0, "Identity already exists");

        // 🔐 hash canónico del CID cifrado
        /* bytes32 encryptedCidHash = keccak256(encryptedCid); */

        // 1️⃣ mensaje firmado por el TEE
        /* bytes32 messageHash = keccak256(
            abi.encode(
                "ISSUE_IDENTITY",
                certId,
                identityCommitment,
                biometricCommitment,
                encryptedCidHash,
                timestamp
            )
        ); */

        bytes32 messageHash = keccak256(
            abi.encode(
                "ISSUE_IDENTITY",
                certId,
                identityCommitment,
                biometricCommitment,
                cid,
                encryptedAESKey,
                timestamp
            )
        );

        // 2️⃣ anti-replay
        require(!usedAuthorizations[messageHash], "Authorization already used");
        usedAuthorizations[messageHash] = true;

        // 3️⃣ recuperar firmante
        bytes32 ethMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );

        address signer = ECDSA.recover(ethMessageHash, signature);
        require(signer == trustedTEE, "Invalid TEE signature");

        // 4️⃣ guardar certificado
        identities[certId] = IdentityCertificate({
            identityCommitment: identityCommitment,
            biometricCommitment: biometricCommitment,
            cid: cid,
            encryptedAESKey: encryptedAESKey,
            issuedAt: block.timestamp,
            revoked: false
        });

        emit IdentityIssued(certId, identityCommitment, block.timestamp);
    }

    /*//////////////////////////////////////////////////////////////
                        CORE: REVOKE IDENTITY
    //////////////////////////////////////////////////////////////*/

    function revokeIdentity(uint256 certId) external onlyOwner {
        IdentityCertificate storage cert = identities[certId];
        require(cert.issuedAt != 0, "Identity does not exist");
        require(!cert.revoked, "Already revoked");

        cert.revoked = true;
        emit IdentityRevoked(certId, block.timestamp);
    }

    /*//////////////////////////////////////////////////////////////
                        VIEW HELPERS
    //////////////////////////////////////////////////////////////*/

    function isValid(uint256 certId) external view returns (bool) {
        IdentityCertificate memory cert = identities[certId];
        return cert.issuedAt != 0 && !cert.revoked;
    }
}
