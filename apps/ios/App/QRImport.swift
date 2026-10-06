import SwiftUI
import VisionKit
import Vision
import ImageIO
import CoreImage

struct QRScanner: UIViewControllerRepresentable {
    let scanned: (String) -> Void
    let failed: () -> Void
    func makeCoordinator() -> Coordinator { Coordinator(scanned: scanned, failed: failed) }
    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])], qualityLevel: .balanced, recognizesMultipleItems: false, isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        do { try scanner.startScanning() } catch { DispatchQueue.main.async { failed() } }
        return scanner
    }
    func updateUIViewController(_ uiViewController: DataScannerViewController, context: Context) {}
    static func dismantleUIViewController(_ controller: DataScannerViewController, coordinator: Coordinator) { controller.stopScanning() }
    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let scanned: (String) -> Void
        let failed: () -> Void
        var finished = false
        init(scanned: @escaping (String) -> Void, failed: @escaping () -> Void) { self.scanned = scanned; self.failed = failed }
        func dataScanner(_ scanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            guard !finished else { return }
            for case .barcode(let code) in addedItems {
                if let raw = code.payloadStringValue, raw.utf8.count <= 1_048_576 {
                    finished = true; scanner.stopScanning(); scanned(raw); return
                }
            }
        }
        func dataScanner(_ dataScanner: DataScannerViewController, becameUnavailableWithError error: DataScannerViewController.ScanningUnavailable) { failed() }
    }
}
enum QRImage {
    static func decode(_ data: Data) throws -> String {
        guard data.count <= 20 * 1024 * 1024, let source = CGImageSourceCreateWithData(data as CFData, nil),
              let image = CGImageSourceCreateThumbnailAtIndex(source, 0, [kCGImageSourceCreateThumbnailFromImageAlways:true, kCGImageSourceThumbnailMaxPixelSize:2048, kCGImageSourceCreateThumbnailWithTransform:true] as CFDictionary) else { throw AppError.message("Cannot read QR image") }
        // Still-image QR decoding does not need a neural-engine context.
        guard let detector = CIDetector(ofType: CIDetectorTypeQRCode,
                                        context: CIContext(options: [.useSoftwareRenderer: true]),
                                        options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]) else {
            throw AppError.message("QR decoder unavailable")
        }
        let values = detector.features(in: CIImage(cgImage: image))
            .compactMap { ($0 as? CIQRCodeFeature)?.messageString }
        guard values.count == 1, let raw = values.first, raw.utf8.count <= 1_048_576 else { throw AppError.message(tr("Choose an image with one QR code", "Выберите изображение с одним QR-кодом")) }
        return raw
    }
}
