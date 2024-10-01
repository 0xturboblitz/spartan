import UIKit

class ViewController: UIViewController {
    
    private let textView = UITextView()
    private let vcAndDiscloseButton = UIButton(type: .system)
    private let rsaButton = UIButton(type: .system)
    private let proveRsaButton = UIButton(type: .system)
    private let proveEcdsaButton = UIButton(type: .system)
    
    private let vcAndDiscloseR1csPath = Bundle.main.path(forResource: "vc_and_disclose", ofType: "r1cs")!
    private let vcAndDiscloseWitnessPath = Bundle.main.path(forResource: "vc_and_disclose", ofType: "wtns")!
    private let rsaR1csPath = Bundle.main.path(forResource: "rsa", ofType: "r1cs")!
    private let rsaWitnessPath = Bundle.main.path(forResource: "rsa", ofType: "wtns")!
    private let proveRsaR1csPath = Bundle.main.path(forResource: "prove_rsa_65537_sha256", ofType: "r1cs")!
    private let proveRsaWitnessPath = Bundle.main.path(forResource: "prove_rsa_65537_sha256", ofType: "wtns")!
    private let proveEcdsaR1csPath = Bundle.main.path(forResource: "prove_ecdsa_secp256r1_sha256", ofType: "r1cs")!
    private let proveEcdsaWitnessPath = Bundle.main.path(forResource: "prove_ecdsa_secp256r1_sha256", ofType: "wtns")!

    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
    }
    
    private func setupUI() {
        view.backgroundColor = .white
        
        vcAndDiscloseButton.setTitle("Run VC and Disclose Benchmark", for: .normal)
        vcAndDiscloseButton.addTarget(self, action: #selector(runVcAndDiscloseBenchmark), for: .touchUpInside)
        
        rsaButton.setTitle("Run RSA Benchmark", for: .normal)
        rsaButton.addTarget(self, action: #selector(runRsaBenchmark), for: .touchUpInside)
        
        proveRsaButton.setTitle("Run Prove RSA 65537 SHA256 Benchmark", for: .normal)
        proveRsaButton.addTarget(self, action: #selector(runProveRsaBenchmark), for: .touchUpInside)
        
        proveEcdsaButton.setTitle("Run Prove ECDSA secp256r1 SHA256 Benchmark", for: .normal)
        proveEcdsaButton.addTarget(self, action: #selector(runProveEcdsaBenchmark), for: .touchUpInside)
        
        textView.isEditable = false
        textView.text = "Results will appear here"
        
        view.addSubview(vcAndDiscloseButton)
        view.addSubview(rsaButton)
        view.addSubview(proveRsaButton)
        view.addSubview(proveEcdsaButton)
        view.addSubview(textView)
        
        vcAndDiscloseButton.translatesAutoresizingMaskIntoConstraints = false
        rsaButton.translatesAutoresizingMaskIntoConstraints = false
        proveRsaButton.translatesAutoresizingMaskIntoConstraints = false
        proveEcdsaButton.translatesAutoresizingMaskIntoConstraints = false
        textView.translatesAutoresizingMaskIntoConstraints = false
        
        NSLayoutConstraint.activate([
            vcAndDiscloseButton.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 20),
            vcAndDiscloseButton.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            
            rsaButton.topAnchor.constraint(equalTo: vcAndDiscloseButton.bottomAnchor, constant: 20),
            rsaButton.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            
            proveRsaButton.topAnchor.constraint(equalTo: rsaButton.bottomAnchor, constant: 20),
            proveRsaButton.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            
            proveEcdsaButton.topAnchor.constraint(equalTo: proveRsaButton.bottomAnchor, constant: 20),
            proveEcdsaButton.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            
            textView.topAnchor.constraint(equalTo: proveEcdsaButton.bottomAnchor, constant: 20),
            textView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20),
            textView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -20),
            textView.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -20)
        ])
    }
    
    @objc private func runVcAndDiscloseBenchmark() {
        runBenchmark(r1csPath: vcAndDiscloseR1csPath, witnessPath: vcAndDiscloseWitnessPath)
    }
    
    @objc private func runRsaBenchmark() {
        runBenchmark(r1csPath: rsaR1csPath, witnessPath: rsaWitnessPath)
    }
    
    @objc private func runProveRsaBenchmark() {
        runBenchmark(r1csPath: proveRsaR1csPath, witnessPath: proveRsaWitnessPath)
    }
    
    @objc private func runProveEcdsaBenchmark() {
        runBenchmark(r1csPath: proveEcdsaR1csPath, witnessPath: proveEcdsaWitnessPath)
    }
    
    private func runBenchmark(r1csPath: String, witnessPath: String) {
        DispatchQueue.global(qos: .userInitiated).async {
            let result = self.runRustBenchmark(r1csPath: r1csPath, witnessPath: witnessPath)
            DispatchQueue.main.async {
                self.textView.text = result
            }
        }
    }
    
    private func runRustBenchmark(r1csPath: String, witnessPath: String) -> String {
        // Ensure the paths are correctly set
        setenv("CIRCOM_R1CS_PATH", r1csPath, 1)
        setenv("CIRCOM_WTNS_PATH", witnessPath, 1)
        
        // Call the Rust function
        let resultPtr = run_benchmark()
        let resultString = String(cString: resultPtr!)
        free_string(resultPtr)
        
        return resultString
    }
}