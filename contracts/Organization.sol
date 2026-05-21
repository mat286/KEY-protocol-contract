// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Organization {
    struct OrganizationData {
        string name;
        address organization;
        address admin;
        uint256 createdAt;
        uint256 updatedAt;
        address[] members;
        string encryptedUrl;
        bool isActive;
    }

    address public immutable owner;
    uint256 public activeOrganizationsCount;
    OrganizationData[] public organizations;

    // organizationId => member => isMember
    mapping(uint256 => mapping(address => bool)) public isMember;

    constructor() {
        owner = msg.sender;
    }

    /* ---------------------------------------- Eventos ---------------------------------------- */

    event OrganizationCreated(
        uint256 indexed organizationId,
        address indexed admin,
        string name
    );

    event OrganizationUpdated(
        uint256 indexed organizationId,
        string name,
        string encryptedUrl
    );

    event MemberAdded(uint256 indexed organizationId, address indexed member);

    event OrganizationStatusChanged(
        uint256 indexed organizationId,
        bool isActive
    );

    event OrganizationDeactivated(
        uint256 indexed organizationId,
        string reason
    );

    /* ---------------------------------------- Modifiers ---------------------------------------- */

    modifier validOrganization(uint256 _organizationId) {
        require(_organizationId < organizations.length, "Invalid organization id");
        _;
    }

    modifier onlyAdmin(uint256 _organizationId) {
        require(
            msg.sender == organizations[_organizationId].admin,
            "Only the admin can perform this action"
        );
        _;
    }

    modifier onlyActive(uint256 _organizationId) {
        require(
            organizations[_organizationId].isActive,
            "Organization is inactive"
        );
        _;
    }

    /* ---------------------------------------- Funciones ---------------------------------------- */

    // Create a new organization
    function createOrganization(
        string memory _name,
        address _organization,
        string memory _encryptedUrl
    ) public {
        require(bytes(_name).length > 0, "Name is required");
        require(_organization != address(0), "Invalid organization address");
        require(bytes(_encryptedUrl).length > 0, "Encrypted URL is required");

        organizations.push(
            OrganizationData({
                name: _name,
                organization: _organization,
                admin: msg.sender,
                createdAt: block.timestamp,
                updatedAt: block.timestamp,
                members: new address[](0),
                encryptedUrl: _encryptedUrl,
                isActive: true
            })
        );

        uint256 organizationId = organizations.length - 1;

        organizations[organizationId].members.push(msg.sender);
        isMember[organizationId][msg.sender] = true;

        ++activeOrganizationsCount;

        emit OrganizationCreated(organizationId, msg.sender, _name);
        emit OrganizationStatusChanged(organizationId, true);
    }

    // Add a member to an organization
    function addMember(
        uint256 _organizationId,
        address _member
    )
        public
        validOrganization(_organizationId)
        onlyAdmin(_organizationId)
        onlyActive(_organizationId)
    {
        require(_member != address(0), "Invalid member address");
        require(
            !isMember[_organizationId][_member],
            "Member already exists"
        );

        organizations[_organizationId].members.push(_member);
        isMember[_organizationId][_member] = true;
        organizations[_organizationId].updatedAt = block.timestamp;

        emit MemberAdded(_organizationId, _member);
    }

    // Update some changes such as name or encryptedUrl
    function updateOrganization(
        uint256 _organizationId,
        string memory _name,
        string memory _encryptedUrl
    )
        public
        validOrganization(_organizationId)
        onlyAdmin(_organizationId)
        onlyActive(_organizationId)
    {
        require(bytes(_name).length > 0, "Name is required");
        require(bytes(_encryptedUrl).length > 0, "Encrypted URL is required");

        organizations[_organizationId].name = _name;
        organizations[_organizationId].encryptedUrl = _encryptedUrl;
        organizations[_organizationId].updatedAt = block.timestamp;

        emit OrganizationUpdated(_organizationId, _name, _encryptedUrl);
    }

    // Deactivate organization
    function deactivateOrganization(
        uint256 _organizationId,
        string memory _reason
    ) public validOrganization(_organizationId) {
        require(
            msg.sender == owner,
            "Only the contract owner can deactivate the organization"
        );
        require(
            organizations[_organizationId].isActive,
            "Organization already inactive"
        );

        organizations[_organizationId].isActive = false;
        organizations[_organizationId].updatedAt = block.timestamp;
        --activeOrganizationsCount;

        emit OrganizationStatusChanged(_organizationId, false);
        emit OrganizationDeactivated(_organizationId, _reason);
    }

    // Get organization details
    function getOrganization(
        uint256 _organizationId
    )
        public
        view
        validOrganization(_organizationId)
        returns (OrganizationData memory)
    {
        return organizations[_organizationId];
    }

    // Get all organizations
    function getOrganizations()
        public
        view
        returns (OrganizationData[] memory)
    {
        return organizations;
    }

    // Get members of an organization
    function getMembers(
        uint256 _organizationId
    )
        public
        view
        validOrganization(_organizationId)
        returns (address[] memory)
    {
        return organizations[_organizationId].members;
    }
}