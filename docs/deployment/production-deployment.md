# Production Deployment Architecture Guide — ARKA

## Kubernetes Architecture

For production scalability, ARKA components deploy to Kubernetes (EKS / GKE / AKS / On-Premise K8s):

- **Backend Ingestion Gateway**: Horizontal Pod Autoscaler (HPA) targeting CPU / HTTP request rate.
- **Kafka**: Multi-node MSK / Strimzi cluster with replication factor 3.
- **OpenSearch**: StatefulSet with dedicated master, data, and ingest nodes.
- **PostgreSQL**: Managed RDS / Cloud SQL with automated failover and read replicas.
- **Reverse Proxy / Ingress**: Nginx Ingress Controller with cert-manager issuing Let's Encrypt / internal mTLS CA certs.
