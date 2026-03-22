from bisect import bisect_left, bisect_right

class BPlusTreeNode:
    def __init__(self, leaf=False):
        self.leaf = leaf
        self.keys = []
        self.values = []
        self.children = []
        self.next = None

class BPlusTree:
    def __init__(self, t=3):
        if t < 2:
            raise ValueError("B+ Tree minimum degree t must be >= 2")
        self.root = BPlusTreeNode(leaf=True)
        self.t = t

    def _find_leaf(self, key):
        node = self.root
        while not node.leaf:
            idx = bisect_right(node.keys, key)
            node = node.children[idx]
        return node

    def _leftmost_leaf(self):
        node = self.root
        while not node.leaf:
            node = node.children[0]
        return node

    def search(self, key):
        leaf = self._find_leaf(key)
        idx = bisect_left(leaf.keys, key)
        if idx < len(leaf.keys) and leaf.keys[idx] == key:
            return leaf.values[idx]
        return None

    def insert(self, key, value):
        root = self.root
        if len(root.keys) == (2 * self.t) - 1:
            temp = BPlusTreeNode()
            self.root = temp
            temp.children.insert(0, root)
            self._split_child(temp, 0)
            self._insert_non_full(temp, key, value)
        else:
            self._insert_non_full(root, key, value)

    def _insert_non_full(self, node, key, value):
        if node.leaf:
            idx = bisect_left(node.keys, key)
            if idx < len(node.keys) and node.keys[idx] == key:
                node.values[idx] = value
                return
            node.keys.insert(idx, key)
            node.values.insert(idx, value)
        else:
            idx = bisect_right(node.keys, key)
            if len(node.children[idx].keys) == (2 * self.t) - 1:
                self._split_child(node, idx)
                if key >= node.keys[idx]:
                    idx += 1
            self._insert_non_full(node.children[idx], key, value)

    def _split_child(self, parent, index):
        t = self.t
        child = parent.children[index]
        new_node = BPlusTreeNode(leaf=child.leaf)

        if child.leaf:
            mid = t - 1
            new_node.keys = child.keys[mid:]
            new_node.values = child.values[mid:]
            child.keys = child.keys[:mid]
            child.values = child.values[:mid]
            new_node.next = child.next
            child.next = new_node

            parent.keys.insert(index, new_node.keys[0])
            parent.children.insert(index + 1, new_node)
        else:
            mid = t - 1
            promote_key = child.keys[mid]
            new_node.keys = child.keys[mid + 1:]
            new_node.children = child.children[mid + 1:]
            child.keys = child.keys[:mid]
            child.children = child.children[:mid + 1]

            parent.keys.insert(index, promote_key)
            parent.children.insert(index + 1, new_node)

    def delete(self, key):
        return self._delete(self.root, key)

    def _delete(self, node, key):
        value = self.search(key)
        if value is None:
            return False

        all_items = self.get_all()
        self.root = BPlusTreeNode(leaf=True)
        for k, v in all_items:
            if k != key:
                self.insert(k, v)
        return True

    def update(self, key, new_value):
        leaf = self._find_leaf(key)
        idx = bisect_left(leaf.keys, key)
        if idx < len(leaf.keys) and leaf.keys[idx] == key:
            leaf.values[idx] = new_value
            return True
        return False

    def range_query(self, start_key, end_key):
        if start_key > end_key:
            return []

        node = self._find_leaf(start_key)
        result = []
        while node:
            for idx, key in enumerate(node.keys):
                if key < start_key:
                    continue
                if key > end_key:
                    return result
                result.append((key, node.values[idx]))
            node = node.next
        return result

    def get_all(self):
        node = self._leftmost_leaf()
        result = []
        while node:
            for idx, key in enumerate(node.keys):
                result.append((key, node.values[idx]))
            node = node.next
        return result

    def visualize_tree(self):
        try:
            from graphviz import Digraph
        except ImportError as exc:
            raise ImportError(
                "graphviz is required for tree visualization. Install with 'pip install graphviz'."
            ) from exc

        dot = Digraph("BPlusTree", node_attr={"shape": "record"})
        self._add_nodes(dot, self.root)
        self._add_edges(dot, self.root)
        return dot

    def _add_nodes(self, dot, node):
        node_id = str(id(node))
        if node.leaf:
            if node.keys:
                pairs = [f"{k}:{node.values[i]}" for i, k in enumerate(node.keys)]
                label = "{Leaf|" + "|".join(pairs) + "}"
            else:
                label = "{Leaf|empty}"
        else:
            if node.keys:
                label = "{Internal|" + "|".join(str(k) for k in node.keys) + "}"
            else:
                label = "{Internal|root}"

        dot.node(node_id, label)
        if not node.leaf:
            for child in node.children:
                self._add_nodes(dot, child)

    def _add_edges(self, dot, node):
        node_id = str(id(node))
        if node.leaf:
            if node.next is not None:
                dot.edge(node_id, str(id(node.next)), style="dashed", color="gray")
            return

        for child in node.children:
            child_id = str(id(child))
            dot.edge(node_id, child_id)
            self._add_edges(dot, child)
