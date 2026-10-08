import datetime
from typing import Dict, Any, List, Optional, Set, Tuple
from collections import deque
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from app.models.models import ObservableEntity, EntityRelation, Incident

class KnowledgeGraphService:
    """
    Observable Knowledge Graph Engine:
    - Extracts multi-domain entities (IP, Host, User, Domain, File Hash)
    - Establishes relational topologies (COMMUNICATED_WITH, LOGGED_INTO, TARGETED, LOCATED_ON)
    - Performs multi-hop BFS graph traversal to compute Incident Blast Radius & Attack Paths.
    """

    @classmethod
    async def upsert_entity(
        cls,
        entity_type: str,
        value: str,
        reputation: str = "unknown",
        metadata: Optional[Dict[str, Any]] = None,
        db=None
    ) -> Optional[ObservableEntity]:
        if not value or not entity_type or not db:
            return None

        clean_val = str(value).strip()
        clean_type = str(entity_type).strip().lower()

        res = await db.execute(
            select(ObservableEntity).where(
                ObservableEntity.entity_type == clean_type,
                ObservableEntity.value == clean_val
            )
        )
        entity = res.scalars().first()

        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        if entity:
            entity.last_seen = now
            entity.incident_count = (entity.incident_count or 1) + 1
            if reputation and reputation != "unknown":
                entity.reputation = reputation
            if metadata:
                existing_meta = dict(entity.metadata_json or {})
                existing_meta.update(metadata)
                entity.metadata_json = existing_meta
        else:
            entity = ObservableEntity(
                entity_type=clean_type,
                value=clean_val,
                reputation=reputation,
                metadata_json=metadata or {},
                first_seen=now,
                last_seen=now,
                incident_count=1
            )
            db.add(entity)

        await db.commit()
        await db.refresh(entity)
        return entity

    @classmethod
    async def create_relation(
        cls,
        source_id: int,
        target_id: int,
        relation_type: str,
        incident_id: Optional[int] = None,
        weight: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
        db=None
    ) -> Optional[EntityRelation]:
        if not source_id or not target_id or source_id == target_id or not db:
            return None

        # Check existing relation
        stmt = select(EntityRelation).where(
            EntityRelation.source_entity_id == source_id,
            EntityRelation.target_entity_id == target_id,
            EntityRelation.relation_type == relation_type
        )
        if incident_id:
            stmt = stmt.where(EntityRelation.incident_id == incident_id)

        res = await db.execute(stmt)
        existing = res.scalars().first()
        if existing:
            return existing

        relation = EntityRelation(
            source_entity_id=source_id,
            target_entity_id=target_id,
            relation_type=relation_type,
            incident_id=incident_id,
            weight=weight,
            context_metadata=metadata or {},
            created_at=datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        )
        db.add(relation)
        await db.commit()
        await db.refresh(relation)
        return relation

    @classmethod
    async def extract_and_ingest_graph(
        cls,
        alert_dict: Dict[str, Any],
        incident_id: Optional[int] = None,
        db=None
    ) -> Dict[str, Any]:
        """
        Extracts entities from alert telemetry and forms relational links with incident tagging.
        """
        if not alert_dict or not db:
            return {"entities_count": 0, "relations_count": 0}

        entities_created: Dict[str, ObservableEntity] = {}

        src_ip = alert_dict.get("source_ip")
        dst_ip = alert_dict.get("destination_ip")
        hostname = alert_dict.get("hostname") or (alert_dict.get("agent_id") if str(alert_dict.get("agent_id", "")).startswith("SRV") else None)
        user = alert_dict.get("user")
        domain = alert_dict.get("domain")
        file_hash = alert_dict.get("file_hash")

        # 1. Upsert Entities
        if src_ip:
            e = await cls.upsert_entity("ip", src_ip, reputation="suspicious", db=db)
            if e: entities_created[f"ip:{src_ip}"] = e

        if dst_ip:
            e = await cls.upsert_entity("ip", dst_ip, reputation="benign", db=db)
            if e: entities_created[f"ip:{dst_ip}"] = e

        if hostname:
            e = await cls.upsert_entity("host", hostname, reputation="benign", db=db)
            if e: entities_created[f"host:{hostname}"] = e

        if user:
            e = await cls.upsert_entity("user", user, reputation="unknown", db=db)
            if e: entities_created[f"user:{user}"] = e

        if domain:
            e = await cls.upsert_entity("domain", domain, reputation="suspicious", db=db)
            if e: entities_created[f"domain:{domain}"] = e

        if file_hash:
            e = await cls.upsert_entity("hash", file_hash, reputation="malicious", db=db)
            if e: entities_created[f"hash:{file_hash}"] = e

        # 2. Establish Topological Relations
        relations_count = 0

        # Src IP -> Dst IP
        if src_ip and dst_ip and f"ip:{src_ip}" in entities_created and f"ip:{dst_ip}" in entities_created:
            await cls.create_relation(
                entities_created[f"ip:{src_ip}"].id,
                entities_created[f"ip:{dst_ip}"].id,
                "COMMUNICATED_WITH",
                incident_id=incident_id,
                db=db
            )
            relations_count += 1

        # Src IP -> Host
        if src_ip and hostname and f"ip:{src_ip}" in entities_created and f"host:{hostname}" in entities_created:
            await cls.create_relation(
                entities_created[f"ip:{src_ip}"].id,
                entities_created[f"host:{hostname}"].id,
                "TARGETED",
                incident_id=incident_id,
                db=db
            )
            relations_count += 1

        # User -> Host
        if user and hostname and f"user:{user}" in entities_created and f"host:{hostname}" in entities_created:
            await cls.create_relation(
                entities_created[f"user:{user}"].id,
                entities_created[f"host:{hostname}"].id,
                "LOGGED_INTO",
                incident_id=incident_id,
                db=db
            )
            relations_count += 1

        # Src IP -> User (Authentication attempt / credential stuffing)
        if src_ip and user and f"ip:{src_ip}" in entities_created and f"user:{user}" in entities_created:
            await cls.create_relation(
                entities_created[f"ip:{src_ip}"].id,
                entities_created[f"user:{user}"].id,
                "AUTHENTICATED_AS",
                incident_id=incident_id,
                db=db
            )
            relations_count += 1

        # File Hash -> Host
        if file_hash and hostname and f"hash:{file_hash}" in entities_created and f"host:{hostname}" in entities_created:
            await cls.create_relation(
                entities_created[f"hash:{file_hash}"].id,
                entities_created[f"host:{hostname}"].id,
                "LOCATED_ON",
                incident_id=incident_id,
                db=db
            )
            relations_count += 1

        # Domain -> Dst IP or Src IP
        if domain and (dst_ip or src_ip) and f"domain:{domain}" in entities_created:
            target_ip_key = f"ip:{dst_ip}" if dst_ip else f"ip:{src_ip}"
            if target_ip_key in entities_created:
                await cls.create_relation(
                    entities_created[f"domain:{domain}"].id,
                    entities_created[target_ip_key].id,
                    "RESOLVED_TO",
                    incident_id=incident_id,
                    db=db
                )
                relations_count += 1

        return {
            "entities_count": len(entities_created),
            "relations_count": relations_count
        }

    @classmethod
    async def get_incident_subgraph(
        cls,
        incident_id: int,
        max_hops: int = 2,
        db=None
    ) -> Dict[str, Any]:
        """
        Traverses multi-hop relations to construct the complete incident knowledge graph
        and calculate the asset Blast Radius score.
        """
        if not db:
            return {"nodes": [], "edges": [], "blast_radius": {}}

        # 1. Fetch direct incident relations
        stmt_direct = select(EntityRelation).where(EntityRelation.incident_id == incident_id)
        res_direct = await db.execute(stmt_direct)
        direct_relations = res_direct.scalars().all()

        visited_nodes: Set[int] = set()
        queue: deque[Tuple[int, int]] = deque() # (entity_id, current_hop)
        collected_relations: Dict[int, EntityRelation] = {}

        for rel in direct_relations:
            collected_relations[rel.id] = rel
            if rel.source_entity_id not in visited_nodes:
                visited_nodes.add(rel.source_entity_id)
                queue.append((rel.source_entity_id, 0))
            if rel.target_entity_id not in visited_nodes:
                visited_nodes.add(rel.target_entity_id)
                queue.append((rel.target_entity_id, 0))

        # 2. Multi-Hop BFS Expansion to uncover shared infrastructure
        while queue:
            curr_id, hop = queue.popleft()
            if hop >= max_hops:
                continue

            # Find adjacent relations in other incidents
            adj_stmt = select(EntityRelation).where(
                (EntityRelation.source_entity_id == curr_id) | (EntityRelation.target_entity_id == curr_id)
            ).limit(20)
            adj_res = await db.execute(adj_stmt)
            for edge in adj_res.scalars().all():
                collected_relations[edge.id] = edge
                neighbor_id = edge.target_entity_id if edge.source_entity_id == curr_id else edge.source_entity_id
                if neighbor_id not in visited_nodes:
                    visited_nodes.add(neighbor_id)
                    queue.append((neighbor_id, hop + 1))

        # 3. Retrieve Entity Node Details
        if not visited_nodes:
            return {
                "nodes": [],
                "edges": [],
                "blast_radius": {
                    "score": 0,
                    "risk_level": "LOW",
                    "affected_hosts": [],
                    "compromised_users": [],
                    "malicious_iocs": []
                }
            }

        ent_stmt = select(ObservableEntity).where(ObservableEntity.id.in_(list(visited_nodes)))
        ent_res = await db.execute(ent_stmt)
        entities = ent_res.scalars().all()

        nodes = []
        affected_hosts = []
        compromised_users = []
        malicious_iocs = []

        for e in entities:
            nodes.append({
                "id": f"entity_{e.id}",
                "entity_id": e.id,
                "label": e.value,
                "type": e.entity_type,
                "reputation": e.reputation,
                "incident_count": e.incident_count,
                "metadata": e.metadata_json or {}
            })
            if e.entity_type == "host":
                affected_hosts.append(e.value)
            elif e.entity_type == "user":
                compromised_users.append(e.value)
            elif e.reputation in ["malicious", "suspicious"]:
                malicious_iocs.append(e.value)

        edges = []
        for r in collected_relations.values():
            edges.append({
                "id": f"rel_{r.id}",
                "source": f"entity_{r.source_entity_id}",
                "target": f"entity_{r.target_entity_id}",
                "relation": r.relation_type,
                "weight": r.weight,
                "incident_id": r.incident_id,
                "metadata": r.context_metadata or {}
            })

        # Calculate Multi-Hop Blast Radius Score (0-100)
        base_score = min(100, (len(affected_hosts) * 25) + (len(compromised_users) * 20) + (len(malicious_iocs) * 15))
        risk_level = "CRITICAL" if base_score >= 75 else ("HIGH" if base_score >= 50 else ("MEDIUM" if base_score >= 25 else "LOW"))

        return {
            "incident_id": incident_id,
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "nodes": nodes,
            "edges": edges,
            "blast_radius": {
                "score": base_score,
                "risk_level": risk_level,
                "affected_hosts": list(set(affected_hosts)),
                "compromised_users": list(set(compromised_users)),
                "malicious_iocs": list(set(malicious_iocs))
            }
        }

    @classmethod
    async def get_entity_graph(
        cls,
        entity_value: str,
        max_hops: int = 2,
        db=None
    ) -> Dict[str, Any]:
        """
        Traverses knowledge graph starting from a specific entity (e.g. IP or Hostname)
        to discover all connected incidents and correlated IOCs.
        """
        if not entity_value or not db:
            return {"nodes": [], "edges": []}

        res = await db.execute(select(ObservableEntity).where(ObservableEntity.value == entity_value.strip()))
        root = res.scalars().first()
        if not root:
            return {"nodes": [], "edges": [], "message": f"Entity '{entity_value}' not found in Knowledge Graph"}

        visited_nodes: Set[int] = {root.id}
        queue: deque[Tuple[int, int]] = deque([(root.id, 0)])
        collected_relations: Dict[int, EntityRelation] = {}

        while queue:
            curr_id, hop = queue.popleft()
            if hop >= max_hops:
                continue

            adj_stmt = select(EntityRelation).where(
                (EntityRelation.source_entity_id == curr_id) | (EntityRelation.target_entity_id == curr_id)
            ).limit(30)
            adj_res = await db.execute(adj_stmt)
            for edge in adj_res.scalars().all():
                collected_relations[edge.id] = edge
                neighbor_id = edge.target_entity_id if edge.source_entity_id == curr_id else edge.source_entity_id
                if neighbor_id not in visited_nodes:
                    visited_nodes.add(neighbor_id)
                    queue.append((neighbor_id, hop + 1))

        ent_stmt = select(ObservableEntity).where(ObservableEntity.id.in_(list(visited_nodes)))
        ent_res = await db.execute(ent_stmt)
        entities = ent_res.scalars().all()

        nodes = [
            {
                "id": f"entity_{e.id}",
                "entity_id": e.id,
                "label": e.value,
                "type": e.entity_type,
                "reputation": e.reputation,
                "incident_count": e.incident_count,
                "is_root": (e.id == root.id)
            }
            for e in entities
        ]

        edges = [
            {
                "id": f"rel_{r.id}",
                "source": f"entity_{r.source_entity_id}",
                "target": f"entity_{r.target_entity_id}",
                "relation": r.relation_type,
                "incident_id": r.incident_id
            }
            for r in collected_relations.values()
        ]

        return {
            "root_entity": {
                "id": root.id,
                "value": root.value,
                "type": root.entity_type,
                "reputation": root.reputation
            },
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "nodes": nodes,
            "edges": edges
        }
