CREATE PROCEDURE [dbo].[ProviderInvoiceItem_Create]
    @Id UNIQUEIDENTIFIER OUTPUT,
    @ProviderId UNIQUEIDENTIFIER,
    @InvoiceId VARCHAR (50),
    @InvoiceNumber VARCHAR (50),
    @ClientName NVARCHAR (50),
    @PlanName NVARCHAR (50),
    @AssignedSeats INT,
    @UsedSeats INT,
    @Total MONEY
AS
BEGIN
    SET NOCOUNT ON

    INSERT INTO [dbo].[ProviderInvoiceItem]
    (
        [Id],
        [ProviderId],
        [InvoiceId],
        [InvoiceNumber],
        [ClientName],
        [PlanName],
        [AssignedSeats],
        [UsedSeats],
        [Total],
        [Created]
    )
    VALUES
    (
        @Id,
        @ProviderId,
        @InvoiceId,
        @InvoiceNumber,
        @ClientName,
        @PlanName,
        @AssignedSeats,
        @UsedSeats,
        @Total,
        GETUTCDATE()
    )
END
