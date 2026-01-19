.PHONY: all build-app build-policy install clean help test-prober

APP_NAME = my_app
POLICY_NAME = my_app
INSTALL_DIR = /usr/local/bin

all: build-app build-policy

# Build the C application
build-app:
	@echo "Building $(APP_NAME)..."
	gcc -Wall -O2 -o $(APP_NAME) $(APP_NAME).c
	@echo "✓ Application built successfully"

# Build SELinux policy using checkmodule and semodule_package
build-policy:
	@echo "Building SELinux policy..."
	@echo "  Compiling policy module..."
	checkmodule -M -m -o $(POLICY_NAME).mod $(POLICY_NAME).te
	@echo "  Creating policy package..."
	semodule_package -o $(POLICY_NAME).pp -m $(POLICY_NAME).mod -f $(POLICY_NAME).fc
	@echo "✓ Policy built successfully"

# Build optimized policy
build-optimized:
	@echo "Building optimized SELinux policy..."
	@echo "  Compiling optimized policy module..."
	checkmodule -M -m -o $(POLICY_NAME).mod $(POLICY_NAME)_optimized.te
	@echo "  Creating optimized policy package..."
	semodule_package -o $(POLICY_NAME).pp -m $(POLICY_NAME).mod -f $(POLICY_NAME).fc
	@echo "✓ Optimized policy built"

# Install application and policy
install: build-app build-policy
	@echo "Installing $(APP_NAME)..."
	sudo cp $(APP_NAME) $(INSTALL_DIR)/
	sudo chmod 755 $(INSTALL_DIR)/$(APP_NAME)
	@echo "Installing SELinux policy..."
	sudo semodule -i $(POLICY_NAME).pp
	@echo "Setting file contexts..."
	sudo restorecon -v $(INSTALL_DIR)/$(APP_NAME)
	@echo ""
	@echo "✓ Installation complete!"
	@echo ""
	@echo "Verify installation:"
	@echo "  sudo semodule -l | grep $(POLICY_NAME)"
	@echo "  ls -Z $(INSTALL_DIR)/$(APP_NAME)"
	@echo ""
	@echo "Run the application:"
	@echo "  sudo $(INSTALL_DIR)/$(APP_NAME)"

# Install optimized policy
install-optimized: build-optimized
	@echo "Installing optimized policy..."
	sudo semodule -u $(POLICY_NAME).pp
	@echo "✓ Optimized policy installed"

# Uninstall
uninstall:
	@echo "Removing application..."
	sudo rm -f $(INSTALL_DIR)/$(APP_NAME)
	@echo "Removing SELinux policy..."
	sudo semodule -r $(POLICY_NAME) 2>/dev/null || true
	@echo "✓ Uninstalled"

# Clean build artifacts
clean:
	rm -f $(APP_NAME)
	rm -f *.pp *.mod
	rm -rf tmp/

# Test with SELinux Prober
test-prober:
	@echo "========================================================"
	@echo "Testing with SELinux Prober"
	@echo "========================================================"
	@echo ""
	@echo "Step 1: Start monitoring"
	@echo "Run: sudo ../selinux-prober my_app_t analyze"
	@echo ""
	@echo "Step 2: Exercise the application"
	@echo "Run: sudo $(INSTALL_DIR)/$(APP_NAME)"
	@echo "      (run it 3-5 times)"
	@echo ""
	@echo "Step 3: Generate report"
	@echo "Run: sudo ../selinux-prober my_app_t report"
	@echo ""
	@echo "Step 4: Review unused permissions"
	@echo "The report will show which permissions were never used"
	@echo ""
	@echo "Step 5: Install optimized policy"
	@echo "Run: make install-optimized"
	@echo ""
	@echo "========================================================"

help:
	@echo "SELinux Demo Application - Makefile targets:"
	@echo ""
	@echo "  make all              - Build application and policy"
	@echo "  make build-app        - Build the C application"
	@echo "  make build-policy     - Build SELinux policy"
	@echo "  make build-optimized  - Build optimized policy"
	@echo "  make install          - Install app and policy"
	@echo "  make install-optimized- Install optimized policy"
	@echo "  make uninstall        - Remove app and policy"
	@echo "  make clean            - Remove build artifacts"
	@echo "  make test-prober      - Show testing instructions"
	@echo ""
	@echo "Quick start:"
	@echo "  1. make install"
	@echo "  2. make test-prober"
	@echo "  3. Follow the instructions"
