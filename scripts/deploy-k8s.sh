#!/bin/bash

# Kubernetes Deployment Script for Billiards Backend
# This script deploys the application to Kubernetes

set -e

echo "🚀 Starting Kubernetes deployment..."

# Check if kubectl is installed
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl is not installed. Please install kubectl first."
    exit 1
fi

# Check if cluster is accessible
if ! kubectl cluster-info &> /dev/null; then
    echo "❌ Cannot connect to Kubernetes cluster. Please check your kubeconfig."
    exit 1
fi

echo "✅ Kubernetes cluster is accessible"

# Create namespace
echo "📦 Creating namespace..."
kubectl apply -f k8s/namespace.yaml

# Apply ConfigMap
echo "⚙️ Applying ConfigMap..."
kubectl apply -f k8s/configmap.yaml

# Apply Secrets
echo "🔐 Applying Secrets..."
kubectl apply -f k8s/secret.yaml

# Run database migration
echo "🗄️ Running database migration..."
kubectl apply -f k8s/migration-job.yaml

# Wait for migration to complete
echo "⏳ Waiting for migration to complete..."
kubectl wait --for=condition=complete job/billiards-migration -n billiards-backend --timeout=300s

# Apply Deployment
echo "🚀 Applying Deployment..."
kubectl apply -f k8s/deployment.yaml

# Apply Service
echo "🌐 Applying Service..."
kubectl apply -f k8s/service.yaml

# Apply Ingress
echo "🔗 Applying Ingress..."
kubectl apply -f k8s/ingress.yaml

# Wait for deployment to be ready
echo "⏳ Waiting for deployment to be ready..."
kubectl rollout status deployment/billiards-backend -n billiards-backend --timeout=300s

# Get service information
echo "📋 Getting service information..."
kubectl get services -n billiards-backend
kubectl get ingress -n billiards-backend

echo "✅ Deployment completed successfully!"
echo "🌐 Your application should be accessible via the ingress URL"
